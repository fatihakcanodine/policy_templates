package mace.intent.evaluate

import future.keywords.if

# ============================================
# CONFIGURATION
# ============================================

valid_action_types := {"SCALE_OUT", "SCALE_IN", "RESTART"}

min_replicas := 1
max_replicas := 16

source_permissions := {
	"AI_AGENT": {"SCALE_OUT", "SCALE_IN"},
	"USER_UI": {"SCALE_OUT", "SCALE_IN", "RESTART"},
	"ADMIN_USER": {"SCALE_OUT", "SCALE_IN", "RESTART"},
}

priority_levels := {"high": 100, "normal": 50, "low": 25}

# ============================================
# HELPERS
# ============================================

get_priority(intent) := intent.priority if {
	intent.priority
	priority_levels[intent.priority]
}

get_priority(intent) := "normal" if {
	not intent.priority
}

get_priority(intent) := "normal" if {
	intent.priority
	not priority_levels[intent.priority]
}

priority_score(intent) := score if {
	score := priority_levels[get_priority(intent)]
}

has_conflict if {
	count(input.activeIntents) > 0
}

source_authorized if {
	some allowed in source_permissions[input.incomingIntent.source]
	input.incomingIntent.actionType == allowed
}

known_source if {
	source_permissions[input.incomingIntent.source]
}

# RESTART doesn't need replica validation
action_needs_replicas if {
	input.incomingIntent.actionType in {"SCALE_OUT", "SCALE_IN"}
}

replicas_valid if {
	not action_needs_replicas
}

replicas_valid if {
	action_needs_replicas
	target := input.incomingIntent.desiredState.target_replicas
	target >= min_replicas
	target <= max_replicas
}

# ============================================
# CONFLICT ANALYSIS
# ============================================

can_override_all if {
	has_conflict
	incoming_score := priority_score(input.incomingIntent)
	every a in input.activeIntents {
		incoming_score > priority_score(a)
	}
}

can_merge if {
	has_conflict
	some a in input.activeIntents
	input.incomingIntent.actionType == a.actionType
	input.incomingIntent.actionType in {"SCALE_OUT", "SCALE_IN"}
	priority_score(input.incomingIntent) == priority_score(a)
}

superseded_intents := [a.intentId |
	has_conflict
	a := input.activeIntents[_]
	priority_score(input.incomingIntent) > priority_score(a)
]

merged_intent_ids := [a.intentId |
	can_merge
	a := input.activeIntents[_]
	input.incomingIntent.actionType == a.actionType
	priority_score(input.incomingIntent) == priority_score(a)
]

# ============================================
# EFFECTIVE TARGET
# ============================================

effective_target := target if {
	can_merge
	incoming := input.incomingIntent.desiredState.target_replicas
	active_targets := [a.desiredState.target_replicas |
		a := input.activeIntents[_]
		input.incomingIntent.actionType == a.actionType
		priority_score(input.incomingIntent) == priority_score(a)
	]
	all_targets := array.concat([incoming], active_targets)
	target := max(all_targets)
}

effective_target := input.incomingIntent.desiredState.target_replicas if {
	not can_merge
	input.incomingIntent.desiredState.target_replicas
}

effective_target := 0 if {
	not can_merge
	not input.incomingIntent.desiredState.target_replicas
}

# ============================================
# DECISION LOGIC
# ============================================

# REJECTED: Unknown source
decision := "REJECTED" if {
	not known_source
}

# REJECTED: Unauthorized action
decision := "REJECTED" if {
	known_source
	not source_authorized
}

# REJECTED: Invalid action type
decision := "REJECTED" if {
	source_authorized
	not valid_action_types[input.incomingIntent.actionType]
}

# REJECTED: Invalid replicas
decision := "REJECTED" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	not replicas_valid
}

# OVERRIDE: Higher priority wins
decision := "OVERRIDE" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	has_conflict
	can_override_all
}

# MERGED: Same priority, same direction
decision := "MERGED" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	has_conflict
	can_merge
	not can_override_all
}

# DEFERRED: Lower/equal priority, not mergeable
decision := "DEFERRED" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	has_conflict
	not can_override_all
	not can_merge
}

# ACCEPTED: No conflict
decision := "ACCEPTED" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	not has_conflict
}

default decision := "REJECTED"

# ============================================
# REASON (Mutually exclusive conditions)
# ============================================

reason := sprintf("Source '%s' not recognized", [input.incomingIntent.source]) if {
	not known_source
}

reason := sprintf("Source '%s' not authorized for '%s'", [
	input.incomingIntent.source, input.incomingIntent.actionType
]) if {
	known_source
	not source_authorized
}

reason := sprintf("Invalid action type: %s", [input.incomingIntent.actionType]) if {
	source_authorized
	not valid_action_types[input.incomingIntent.actionType]
}

reason := sprintf("Replicas %d out of range [%d-%d]", [
	input.incomingIntent.desiredState.target_replicas, min_replicas, max_replicas
]) if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	not replicas_valid
}

reason := sprintf("%s priority overrides %d intent(s)", [
	get_priority(input.incomingIntent), count(superseded_intents)
]) if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	can_override_all
}

reason := sprintf("Merged with %d intent(s) at %s priority", [
	count(merged_intent_ids), get_priority(input.incomingIntent)
]) if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	can_merge
	not can_override_all
}

reason := "Deferred: waiting for active intent completion" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	has_conflict
	not can_override_all
	not can_merge
}

reason := "Accepted for processing" if {
	source_authorized
	valid_action_types[input.incomingIntent.actionType]
	replicas_valid
	not has_conflict
}

# ============================================
# CONFLICT RESOLUTION
# ============================================

conflict_resolution := {
	"resolved": true,
	"type": "override",
	"supersededIntents": superseded_intents,
	"reason": sprintf("%s priority override", [get_priority(input.incomingIntent)])
} if {
	can_override_all
}

conflict_resolution := {
	"resolved": true,
	"type": "merge",
	"mergedFrom": merged_intent_ids,
	"effectiveTarget": effective_target,
	"reason": sprintf("Merged at %s priority", [get_priority(input.incomingIntent)])
} if {
	can_merge
	not can_override_all
}

conflict_resolution := {
	"resolved": false,
	"type": "deferred",
	"reason": "Waiting for active intent completion"
} if {
	has_conflict
	not can_override_all
	not can_merge
}

conflict_resolution := {
	"resolved": true,
	"type": "none",
	"reason": "No conflict"
} if {
	not has_conflict
}

# ============================================
# RESULT
# ============================================

result := {
	"decision": decision,
	"reason": reason,
	"actionClass": "DISRUPTIVE_BOUNDED",
	"effectiveIntent": {
		"intentId": input.incomingIntent.intentId,
		"targetReplicas": effective_target,
		"mergedFrom": merged_intent_ids
	},
	"priority": {
		"level": priority_score(input.incomingIntent),
		"label": get_priority(input.incomingIntent)
	},
	"conflictResolution": conflict_resolution
}
