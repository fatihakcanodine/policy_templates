package mace.cnf.domain

import future.keywords.if
import future.keywords.in

# ============================================
# REACTIVE RULE EVALUATION — Tests
# ============================================

# -------------------------------------------
# Mock data fixtures (same as policy_test.rego)
# -------------------------------------------

mock_reactive_platform_routing := {
	"notify":           {"executor": "obs",          "scope": "LOCAL"},
	"open_ticket":      {"executor": "itsm-manager", "scope": "GLOBAL"},
	"suppress_alarm":   {"executor": "obs",          "scope": "GLOBAL"},
	"audit_flag":       {"executor": "obs",          "scope": "LOCAL"},
}

mock_reactive_domain_routing := {
	"scale_out":        {"executor": "cnf-manager", "scope": "GLOBAL"},
	"scale_in":         {"executor": "cnf-manager", "scope": "GLOBAL"},
	"restart_workload": {"executor": "cnf-manager", "scope": "GLOBAL"},
	"config_update":    {"executor": "cnf-manager", "scope": "GLOBAL"},
	"drain_node":       {"executor": "cnf-manager", "scope": "GLOBAL"},
}

mock_reactive_platform_taxonomy := {
	"notify":             {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"deny":               {"base_risk": 10, "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"allow":              {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"open_ticket":        {"base_risk": 5,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"suppress_alarm":     {"base_risk": 5,  "cooldown_seconds": 60,  "action_class": "NON_DISRUPTIVE"},
	"audit_flag":         {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
}

mock_reactive_domain_taxonomy := {
	"scale_out":          {"base_risk": 30, "cooldown_seconds": 300, "action_class": "DISRUPTIVE_BOUNDED"},
	"scale_in":           {"base_risk": 50, "cooldown_seconds": 300, "action_class": "DISRUPTIVE_BOUNDED"},
	"restart_workload":   {"base_risk": 70, "cooldown_seconds": 600, "action_class": "DISRUPTIVE_UNBOUNDED"},
	"drain_node":         {"base_risk": 80, "cooldown_seconds": 900, "action_class": "DISRUPTIVE_UNBOUNDED"},
	"config_update":      {"base_risk": 20, "cooldown_seconds": 60,  "action_class": "NON_DISRUPTIVE"},
}

mock_reactive_priority_levels := {"critical": 1, "high": 2, "normal": 5, "medium": 5, "low": 10}

mock_reactive_operator_limits := {
	"max_replicas_per_tenant": 20,
	"max_risk_score": 90,
	"bypass_priorities": ["critical"],
}

mock_reactive_tenants := {
	"enterprise-x": {
		"constraints": {
			"max_replicas": 10,
			"allowed_actions": ["scale_out", "scale_in", "config_update", "restart_workload", "drain_node"],
		},
	},
	"enterprise-y": {
		"constraints": {
			"max_replicas": 5,
			"allowed_actions": ["scale_out", "config_update"],
		},
	},
}

mock_reactive_meta := {"policy_revision": "test-1.0.0"}

# -------------------------------------------
# Mock reactive rules — domain default
# -------------------------------------------

mock_domain_reactive_rules := {
	"rules": [
		{
			"id": "nginx-fallback",
			"description": "When nginx-app scales down, scale up nginx-2-app",
			"enabled": true,
			"trigger": {
				"kind": "Deployment",
				"name": "mace-dummy-nginx-app",
				"reason": "ScalingReplicaSet",
				"condition": {"field": "replicas", "operator": "lte", "value": 1},
			},
			"action": {
				"effect_type": "scale_out",
				"target": {"name": "mace-dummy-nginx-2-app"},
				"params": {"delta": 2},
			},
		},
	],
}

# -------------------------------------------
# Helpers: evaluate with full mock context
# -------------------------------------------

evaluate_reactive_with_mocks(event_input) := result if {
	result := data.mace.cnf.domain.evaluate
		with input as event_input
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as mock_reactive_operator_limits
		with data.mace.cnf.tenants as mock_reactive_tenants
		with data.mace.cnf.domain.reactive_rules as mock_domain_reactive_rules
}

# Tenant override variant — enterprise-x overrides threshold and delta
evaluate_reactive_tenant_override(tenant_id, event_input) := result if {
	tenants_with_overrides := object.union(mock_reactive_tenants, {
		"enterprise-x": {
			"constraints": mock_reactive_tenants["enterprise-x"].constraints,
			"reactive_rules": {
				"rules": [
					{
						"id": "nginx-fallback",
						"description": "enterprise-x: override",
						"trigger": {
							"kind": "Deployment",
							"name": "mace-dummy-nginx-app",
							"reason": "ScalingReplicaSet",
							"condition": {"field": "replicas", "operator": "lte", "value": 2},
						},
						"action": {
							"effect_type": "scale_out",
							"target": {"name": "mace-dummy-nginx-2-app"},
							"params": {"delta": 3},
						},
					},
				],
			},
		},
		"enterprise-y": {
			"constraints": mock_reactive_tenants["enterprise-y"].constraints,
			"reactive_rules": {
				"rules": [
					{"id": "nginx-fallback", "enabled": false},
				],
			},
		},
	})

	result := data.mace.cnf.domain.evaluate
		with input as object.union(event_input, {"tenant_id": tenant_id})
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as mock_reactive_operator_limits
		with data.mace.cnf.tenants as tenants_with_overrides
		with data.mace.cnf.domain.reactive_rules as mock_domain_reactive_rules
}

base_event := {
	"kind": "Deployment",
	"name": "mace-dummy-nginx-app",
	"namespace": "default",
	"cluster_id": "cluster-1",
	"reason": "ScalingReplicaSet",
	"replicas": 1,
}

base_reactive_input := {
	"tenant_id": "enterprise-x",
	"source": "reactive-evaluator",
	"incident_id": "test-incident-001",
	"event": base_event,
}

# -------------------------------------------
# Test 1: nginx-fallback triggers (happy path)
# -------------------------------------------

test_reactive_nginx_fallback_triggers if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.scope == "GLOBAL"
	e.risk_score == 30
	e.action_class == "DISRUPTIVE_BOUNDED"
	e.cooldown_seconds == 300
	e.effect_params.target_replicas == 2
	e.effect_params.reactive_rule_id == "nginx-fallback"
	e.target_ref.name == "mace-dummy-nginx-2-app"
	e.target_ref.cluster_id == "cluster-1"
	e.target_ref.namespace == "default"
}

# -------------------------------------------
# Test 2: Wrong kind → no match
# -------------------------------------------

test_reactive_no_match_wrong_kind if {
	eval := evaluate_reactive_with_mocks(object.union(base_reactive_input, {
		"event": object.union(base_event, {"kind": "Pod"}),
	}))
	count(eval.effects) == 0
}

# -------------------------------------------
# Test 3: Wrong reason → no match
# -------------------------------------------

test_reactive_no_match_wrong_reason if {
	eval := evaluate_reactive_with_mocks(object.union(base_reactive_input, {
		"event": object.union(base_event, {"reason": "Killing"}),
	}))
	count(eval.effects) == 0
}

# -------------------------------------------
# Test 4: Condition not met (replicas=3)
# -------------------------------------------

test_reactive_no_match_condition_not_met if {
	eval := evaluate_reactive_with_mocks(object.union(base_reactive_input, {
		"event": object.union(base_event, {"replicas": 3}),
	}))
	count(eval.effects) == 0
}

# -------------------------------------------
# Test 5: Tenant override changes threshold
# -------------------------------------------

test_reactive_tenant_override_changes_threshold if {
	# enterprise-x overrides to lte 2, replicas=2 should trigger
	eval := evaluate_reactive_tenant_override("enterprise-x", {
		"source": "reactive-evaluator",
		"incident_id": "test-override-001",
		"event": object.union(base_event, {"replicas": 2}),
	})
	count(eval.effects) == 1
	eval.effects[0].effect_type == "scale_out"
}

# -------------------------------------------
# Test 6: Tenant override changes delta
# -------------------------------------------

test_reactive_tenant_override_changes_delta if {
	eval := evaluate_reactive_tenant_override("enterprise-x", base_reactive_input)
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_params.target_replicas == 3  # overridden from 2 to 3
}

# -------------------------------------------
# Test 7: Tenant disable rule
# -------------------------------------------

test_reactive_tenant_disable_rule if {
	eval := evaluate_reactive_tenant_override("enterprise-y", base_reactive_input)
	count(eval.effects) == 0
}

# -------------------------------------------
# Test 8: Unauthorized effect → deny
# -------------------------------------------

test_reactive_unauthorized_effect_denied if {
	# Create a tenant that does NOT have scale_out in allowed_actions
	restricted_tenants := {
		"restricted-tenant": {
			"constraints": {
				"max_replicas": 10,
				"allowed_actions": ["config_update"],
			},
		},
	}
	eval := data.mace.cnf.domain.evaluate
		with input as object.union(base_reactive_input, {"tenant_id": "restricted-tenant"})
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as mock_reactive_operator_limits
		with data.mace.cnf.tenants as restricted_tenants
		with data.mace.cnf.domain.reactive_rules as mock_domain_reactive_rules
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "deny"
	contains(e.effect_params.reason, "not authorized")
}

# -------------------------------------------
# Test 9: Replica limit exceeded → deny
# -------------------------------------------

test_reactive_replica_limit_exceeded_denied if {
	# delta=2 but operator limit is only 1
	strict_limits := {
		"max_replicas_per_tenant": 1,
		"max_risk_score": 90,
		"bypass_priorities": [],
	}
	eval := data.mace.cnf.domain.evaluate
		with input as base_reactive_input
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as strict_limits
		with data.mace.cnf.tenants as mock_reactive_tenants
		with data.mace.cnf.domain.reactive_rules as mock_domain_reactive_rules
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "deny"
	contains(e.effect_params.reason, "replica limits")
}

# -------------------------------------------
# Test 10: No input.event → request-driven path
# -------------------------------------------

test_reactive_event_missing_no_reactive if {
	eval := data.mace.cnf.domain.evaluate
		with input as {"action": "scale_out", "tenant_id": "enterprise-x", "target_replicas": 3}
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as mock_reactive_operator_limits
		with data.mace.cnf.tenants as mock_reactive_tenants
		with data.mace.cnf.domain.reactive_rules as mock_domain_reactive_rules
	count(eval.effects) == 1
	eval.effects[0].effect_type == "scale_out"
	eval.source == "unknown"
}

# -------------------------------------------
# Test 11: Multiple rules match → multiple effects
# -------------------------------------------

test_reactive_multiple_rules_matching if {
	multi_rules := {
		"rules": [
			{
				"id": "nginx-fallback",
				"enabled": true,
				"trigger": {
					"kind": "Deployment",
					"name": "mace-dummy-nginx-app",
					"reason": "ScalingReplicaSet",
					"condition": {"field": "replicas", "operator": "lte", "value": 1},
				},
				"action": {
					"effect_type": "scale_out",
					"target": {"name": "mace-dummy-nginx-2-app"},
					"params": {"delta": 2},
				},
			},
			{
				"id": "nginx-notify",
				"enabled": true,
				"trigger": {
					"kind": "Deployment",
					"name": "mace-dummy-nginx-app",
					"reason": "ScalingReplicaSet",
					"condition": {"field": "replicas", "operator": "lte", "value": 1},
				},
				"action": {
					"effect_type": "restart_workload",
					"target": {"name": "mace-dummy-nginx-app"},
					"params": {},
				},
			},
		],
	}
	eval := data.mace.cnf.domain.evaluate
		with input as base_reactive_input
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as mock_reactive_operator_limits
		with data.mace.cnf.tenants as mock_reactive_tenants
		with data.mace.cnf.domain.reactive_rules as multi_rules
	count(eval.effects) == 2
	types := {e.effect_type | e := eval.effects[_]}
	"scale_out" in types
	"restart_workload" in types
}

# -------------------------------------------
# Test 12: effect_key format
# -------------------------------------------

test_reactive_effect_key_format if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	count(eval.effects) == 1
	startswith(eval.effects[0].effect_key, "reactive:scale_out:enterprise-x:mace-dummy-nginx-2-app")
}

# -------------------------------------------
# Test 13: Output required fields
# -------------------------------------------

test_reactive_output_has_required_fields if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	eval.source == "reactive-evaluator"
	eval.tenant_id == "enterprise-x"
	eval.incident_id == "test-incident-001"
	eval.policy_revision == "test-1.0.0"
}

# -------------------------------------------
# Test 14: Scope from routing
# -------------------------------------------

test_reactive_scope_from_routing if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	eval.effects[0].scope == "GLOBAL"
}

# -------------------------------------------
# Test 15: Risk score from taxonomy
# -------------------------------------------

test_reactive_risk_score_from_taxonomy if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	eval.effects[0].risk_score == 30
}

# -------------------------------------------
# Test 16: Action class from taxonomy
# -------------------------------------------

test_reactive_action_class_from_taxonomy if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	eval.effects[0].action_class == "DISRUPTIVE_BOUNDED"
}

# -------------------------------------------
# Test 17: Cross-resource target_ref
# -------------------------------------------

test_reactive_target_ref_cross_resource if {
	eval := evaluate_reactive_with_mocks(base_reactive_input)
	e := eval.effects[0]
	e.target_ref.name == "mace-dummy-nginx-2-app"
	# Input event was about mace-dummy-nginx-app, but effect targets mace-dummy-nginx-2-app
	e.target_ref.name != base_event.name
}

# -------------------------------------------
# Test 18: Empty rules → zero effects
# -------------------------------------------

test_reactive_no_rules_no_effects if {
	empty_rules := {"rules": []}
	eval := data.mace.cnf.domain.evaluate
		with input as base_reactive_input
		with data.mace.platform.effect_routing as mock_reactive_platform_routing
		with data.mace.platform.effect_taxonomy as mock_reactive_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_reactive_domain_taxonomy
		with data.mace.platform.priority_levels as mock_reactive_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_reactive_domain_routing
		with data.mace.cnf.domain.meta as mock_reactive_meta
		with data.mace.cnf.operator.limits as mock_reactive_operator_limits
		with data.mace.cnf.tenants as mock_reactive_tenants
		with data.mace.cnf.domain.reactive_rules as empty_rules
	count(eval.effects) == 0
}
