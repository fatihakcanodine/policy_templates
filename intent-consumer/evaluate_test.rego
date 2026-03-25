package mace.intent.evaluate

import future.keywords.if

# ============================================
# UNIT TESTS - Helper Functions
# ============================================

# Priority score tests
test_priority_score_high if {
	priority_score({"priority": "high"}) == 100
}

test_priority_score_normal if {
	priority_score({"priority": "normal"}) == 50
}

test_priority_score_low if {
	priority_score({"priority": "low"}) == 25
}

test_priority_score_default if {
	priority_score({}) == 50
}

# Conflict detection tests
test_has_conflict_true if {
	has_conflict with input as {"activeIntents": [{"intentId": "1"}]}
}

test_has_conflict_false if {
	not has_conflict with input as {"activeIntents": []}
}

# Source authorization tests
test_source_authorized_ai_agent_scale_out if {
	source_authorized with input as {"incomingIntent": {"source": "AI_AGENT", "actionType": "SCALE_OUT"}}
}

test_source_authorized_user_restart if {
	source_authorized with input as {"incomingIntent": {"source": "USER_UI", "actionType": "RESTART"}}
}

test_source_not_authorized_ai_restart if {
	not source_authorized with input as {"incomingIntent": {"source": "AI_AGENT", "actionType": "RESTART"}}
}

# Known source tests
test_known_source_true if {
	known_source with input as {"incomingIntent": {"source": "AI_AGENT"}}
}

test_known_source_false if {
	not known_source with input as {"incomingIntent": {"source": "UNKNOWN"}}
}

# Replica validation tests
test_replicas_valid_no_target if {
	replicas_valid with input as {"incomingIntent": {"actionType": "RESTART", "desiredState": {}}}
}

test_replicas_valid_in_range if {
	replicas_valid with input as {"incomingIntent": {"actionType": "SCALE_OUT", "desiredState": {"target_replicas": 5}}}
}

test_replicas_invalid_low if {
	not replicas_valid with input as {"incomingIntent": {"actionType": "SCALE_IN", "desiredState": {"target_replicas": 0}}}
}

test_replicas_invalid_high if {
	not replicas_valid with input as {"incomingIntent": {"actionType": "SCALE_OUT", "desiredState": {"target_replicas": 15}}}
}

# ============================================
# INTEGRATION TESTS
# ============================================

# Test 1: ACCEPTED - No conflict
test_accepted_no_conflict if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-1",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 5},
			"priority": "normal"
		},
		"activeIntents": []
	}
	res.decision == "ACCEPTED"
}

# Test 2: REJECTED - Unknown source
test_rejected_unknown_source if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-2",
			"source": "UNKNOWN",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 5}
		},
		"activeIntents": []
	}
	res.decision == "REJECTED"
}

# Test 3: REJECTED - Unauthorized action (AI_AGENT cannot RESTART)
test_rejected_unauthorized_action if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-3",
			"source": "AI_AGENT",
			"actionType": "RESTART",
			"desiredState": {}
		},
		"activeIntents": []
	}
	res.decision == "REJECTED"
}

# Test 4: REJECTED - Invalid action type (DELETE not in valid_action_types)
test_rejected_invalid_action_type if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-4",
			"source": "ADMIN_USER",
			"actionType": "DELETE",
			"desiredState": {}
		},
		"activeIntents": []
	}
	res.decision == "REJECTED"
}

# Test 5: REJECTED - Replicas exceed max
test_rejected_exceed_max if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-5",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 15}
		},
		"activeIntents": []
	}
	res.decision == "REJECTED"
}

# Test 6: REJECTED - Replicas below min
test_rejected_below_min if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-6",
			"source": "AI_AGENT",
			"actionType": "SCALE_IN",
			"desiredState": {"target_replicas": 0}
		},
		"activeIntents": []
	}
	res.decision == "REJECTED"
}

# Test 7: OVERRIDE - High priority over normal
test_override_high_over_normal if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-7",
			"source": "ADMIN_USER",
			"actionType": "SCALE_IN",
			"desiredState": {"target_replicas": 2},
			"priority": "high"
		},
		"activeIntents": [
			{
				"intentId": "active-1",
				"source": "AI_AGENT",
				"actionType": "SCALE_OUT",
				"desiredState": {"target_replicas": 5},
				"priority": "normal"
			}
		]
	}
	res.decision == "OVERRIDE"
	res.conflictResolution.type == "override"
}

# Test 8: DEFERRED - Low vs high priority
test_deferred_low_priority if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-8",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 7},
			"priority": "low"
		},
		"activeIntents": [
			{
				"intentId": "active-1",
				"source": "ADMIN_USER",
				"actionType": "SCALE_IN",
				"desiredState": {"target_replicas": 2},
				"priority": "high"
			}
		]
	}
	res.decision == "DEFERRED"
}

# Test 9: MERGED - Same priority, same direction
test_merged_same_direction if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-9",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 7},
			"priority": "normal"
		},
		"activeIntents": [
			{
				"intentId": "active-1",
				"source": "AI_AGENT",
				"actionType": "SCALE_OUT",
				"desiredState": {"target_replicas": 5},
				"priority": "normal"
			}
		]
	}
	res.decision == "MERGED"
	res.conflictResolution.type == "merge"
}

# Test 10: DEFERRED - Same priority, opposite direction
test_deferred_opposite_direction if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-10",
			"source": "AI_AGENT",
			"actionType": "SCALE_IN",
			"desiredState": {"target_replicas": 2},
			"priority": "normal"
		},
		"activeIntents": [
			{
				"intentId": "active-1",
				"source": "AI_AGENT",
				"actionType": "SCALE_OUT",
				"desiredState": {"target_replicas": 5},
				"priority": "normal"
			}
		]
	}
	res.decision == "DEFERRED"
}

# Test 11: Priority info
test_priority_info if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-11",
			"source": "ADMIN_USER",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 5},
			"priority": "high"
		},
		"activeIntents": []
	}
	res.priority.label == "high"
	res.priority.level == 100
}

# Test 12: Default priority
test_default_priority if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-12",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 5}
		},
		"activeIntents": []
	}
	res.priority.label == "normal"
	res.priority.level == 50
}

# Test 13: RESTART authorized for USER_UI
test_restart_authorized_user if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-13",
			"source": "USER_UI",
			"actionType": "RESTART",
			"desiredState": {}
		},
		"activeIntents": []
	}
	res.decision == "ACCEPTED"
}

# Test 14: Conflict resolution superseded intents
test_superseded_intents_list if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-14",
			"source": "ADMIN_USER",
			"actionType": "SCALE_IN",
			"desiredState": {"target_replicas": 2},
			"priority": "high"
		},
		"activeIntents": [
			{
				"intentId": "active-1",
				"actionType": "SCALE_OUT",
				"desiredState": {"target_replicas": 5},
				"priority": "normal"
			},
			{
				"intentId": "active-2",
				"actionType": "SCALE_OUT",
				"desiredState": {"target_replicas": 3},
				"priority": "low"
			}
		]
	}
	res.decision == "OVERRIDE"
	"active-1" in res.conflictResolution.supersededIntents
	"active-2" in res.conflictResolution.supersededIntents
}

# Test 15: Merged effective target is max
test_merged_effective_target if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-15",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 7},
			"priority": "normal"
		},
		"activeIntents": [
			{
				"intentId": "active-1",
				"actionType": "SCALE_OUT",
				"desiredState": {"target_replicas": 5},
				"priority": "normal"
			}
		]
	}
	res.decision == "MERGED"
	res.conflictResolution.effectiveTarget == 7
}

# Test 16: Valid replicas at boundaries
test_replicas_boundary_min if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-16",
			"source": "AI_AGENT",
			"actionType": "SCALE_IN",
			"desiredState": {"target_replicas": 1}
		},
		"activeIntents": []
	}
	res.decision == "ACCEPTED"
}

test_replicas_boundary_max if {
	res := result with input as {
		"incomingIntent": {
			"intentId": "test-17",
			"source": "AI_AGENT",
			"actionType": "SCALE_OUT",
			"desiredState": {"target_replicas": 10}
		},
		"activeIntents": []
	}
	res.decision == "ACCEPTED"
}
