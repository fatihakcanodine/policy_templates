package mace.cnf.domain

import future.keywords.if

# ============================================
# CNF DOMAIN POLICY — Tests
# ============================================
# Tests mock cross-layer data using `with` statements:
#   - data.mace.platform.effect_routing
#   - data.mace.platform.effect_taxonomy (platform effects only)
#   - data.mace.cnf.domain.taxonomy    (domain effects only)
#   - data.mace.platform.priority_levels
#   - data.mace.cnf.operator.limits
#   - data.mace.cnf.tenants

# -------------------------------------------
# Mock data fixtures
# -------------------------------------------

mock_platform_routing := {
	"notify":           {"executor": "obs",          "scope": "LOCAL"},
	"open_ticket":      {"executor": "itsm-manager", "scope": "GLOBAL"},
	"suppress_alarm":   {"executor": "obs",          "scope": "GLOBAL"},
	"audit_flag":       {"executor": "obs",          "scope": "LOCAL"},
}

mock_domain_routing := {
	"scale_out":        {"executor": "cnf-manager", "scope": "GLOBAL"},
	"scale_in":         {"executor": "cnf-manager", "scope": "GLOBAL"},
	"restart_workload": {"executor": "cnf-manager", "scope": "GLOBAL"},
	"config_update":    {"executor": "cnf-manager", "scope": "GLOBAL"},
	"drain_node":       {"executor": "cnf-manager", "scope": "GLOBAL"},
}

mock_platform_taxonomy := {
	"notify":             {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"deny":               {"base_risk": 10, "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"allow":              {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"open_ticket":        {"base_risk": 5,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"suppress_alarm":     {"base_risk": 5,  "cooldown_seconds": 60,  "action_class": "NON_DISRUPTIVE"},
	"audit_flag":         {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
}

mock_domain_taxonomy := {
	"scale_out":          {"base_risk": 30, "cooldown_seconds": 300, "action_class": "DISRUPTIVE_BOUNDED"},
	"scale_in":           {"base_risk": 50, "cooldown_seconds": 300, "action_class": "DISRUPTIVE_BOUNDED"},
	"restart_workload":   {"base_risk": 70, "cooldown_seconds": 600, "action_class": "DISRUPTIVE_UNBOUNDED"},
	"drain_node":         {"base_risk": 80, "cooldown_seconds": 900, "action_class": "DISRUPTIVE_UNBOUNDED"},
	"config_update":      {"base_risk": 20, "cooldown_seconds": 60,  "action_class": "NON_DISRUPTIVE"},
}

mock_priority_levels := {"critical": 1, "high": 2, "normal": 5, "medium": 5, "low": 10}

mock_operator_limits := {
	"max_replicas_per_tenant": 20,
	"max_risk_score": 90,
	"bypass_priorities": ["critical"],
}

mock_tenants := {
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

# -------------------------------------------
# Helper: evaluate with full mock context
# -------------------------------------------

mock_meta := {"policy_revision": "test-1.0.0"}

evaluate_with_mocks(action_input) := result if {
	result := data.mace.cnf.domain.evaluate
		with input as action_input
		with data.mace.platform.effect_routing as mock_platform_routing
		with data.mace.platform.effect_taxonomy as mock_platform_taxonomy
		with data.mace.cnf.domain.taxonomy as mock_domain_taxonomy
		with data.mace.platform.priority_levels as mock_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_domain_routing
		with data.mace.cnf.domain.meta as mock_meta
		with data.mace.cnf.operator.limits as mock_operator_limits
		with data.mace.cnf.tenants as mock_tenants
}

# -------------------------------------------
# SCALE_OUT Tests
# -------------------------------------------

test_scale_out_enterprise_x if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.scope == "GLOBAL"
	e.risk_score == 30
	e.cooldown_seconds == 300
	e.action_class == "DISRUPTIVE_BOUNDED"
	e.effect_params.target_replicas == 3
}

test_scale_out_custom_replicas if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
		"target_replicas": 7,
	})
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.effect_params.target_replicas == 7
}

test_scale_out_exceeds_tenant_max_replicas_denied if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
		"target_replicas": 15,
	})
	# enterprise-x max_replicas is 10, requesting 15 -> deny
	e := eval.effects[0]
	e.effect_type == "deny"
}

test_scale_out_exceeds_operator_max_denied if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
		"target_replicas": 25,
	})
	# operator max_replicas_per_tenant is 20, requesting 25 -> deny
	e := eval.effects[0]
	e.effect_type == "deny"
}

# -------------------------------------------
# SCALE_IN Tests
# -------------------------------------------

test_scale_in_enterprise_x if {
	eval := evaluate_with_mocks({
		"action": "scale_in",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-2",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "scale_in"
	e.scope == "GLOBAL"
	e.risk_score == 50
}

# -------------------------------------------
# CONFIG_UPDATE Tests
# -------------------------------------------

test_config_update_enterprise_x if {
	eval := evaluate_with_mocks({
		"action": "config_update",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-3",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "config_update"
	e.risk_score == 20
	e.cooldown_seconds == 60
}

# -------------------------------------------
# RESTART_WORKLOAD Tests
# -------------------------------------------

test_restart_workload if {
	eval := evaluate_with_mocks({
		"action": "restart_workload",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-4",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "high",
	})
	e := eval.effects[0]
	e.effect_type == "restart_workload"
	e.scope == "GLOBAL"
	e.risk_score == 70
	e.action_class == "DISRUPTIVE_UNBOUNDED"
	e.priority == 2
}

# -------------------------------------------
# DRAIN_NODE Tests
# -------------------------------------------

test_drain_node if {
	eval := evaluate_with_mocks({
		"action": "drain_node",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-5",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "node-1"},
		"priority": "critical",
	})
	e := eval.effects[0]
	e.effect_type == "drain_node"
	e.scope == "GLOBAL"
	e.risk_score == 80
	e.priority == 1
}

# -------------------------------------------
# NOTIFY Tests
# -------------------------------------------

test_notify_local if {
	eval := evaluate_with_mocks({
		"action": "notify",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-6",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "notify"
	e.scope == "LOCAL"
	e.risk_score == 0
}

# -------------------------------------------
# Tenant Authorization Tests
# -------------------------------------------

test_scale_in_not_authorized_for_enterprise_y if {
	eval := evaluate_with_mocks({
		"action": "scale_in",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-7",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	# enterprise-y allowed_actions: ["scale_out", "config_update"] — no scale_in
	e := eval.effects[0]
	e.effect_type == "deny"
}

test_restart_workload_not_authorized_for_enterprise_y if {
	eval := evaluate_with_mocks({
		"action": "restart_workload",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-8",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	# enterprise-y does not have restart_workload in allowed_actions
	e := eval.effects[0]
	e.effect_type == "deny"
}

# -------------------------------------------
# Fail-Closed Tests
# -------------------------------------------

test_unknown_action_denied if {
	eval := evaluate_with_mocks({
		"action": "nonexistent_action",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-9",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "deny"
	e.scope == "LOCAL"
}

# -------------------------------------------
# Output Structure Tests
# -------------------------------------------

test_evaluate_has_required_fields if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	eval.effects
	eval.source == "test-source"
	eval.tenant_id == "enterprise-x"
	eval.incident_id == "inc-1"
}

test_evaluate_default_values if {
	eval := evaluate_with_mocks({
		"action": "notify",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"priority": "normal",
	})
	eval.source == "unknown"
}

# -------------------------------------------
# Priority Tests
# -------------------------------------------

test_critical_priority if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "critical",
	})
	e := eval.effects[0]
	e.priority == 1
}

test_default_priority if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "unknown_priority",
	})
	e := eval.effects[0]
	e.priority == 5
}

test_evaluate_has_policy_revision if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	eval.policy_revision == "test-1.0.0"
}


# -------------------------------------------
# NEW TEST SCENARIOS
# -------------------------------------------

# 1. scale_out for enterprise-y with default replicas (3) -- should succeed
#    enterprise-y max_replicas=5, default target_replicas=3 <= 5, within operator limit 20
test_scale_out_enterprise_y_default_replicas if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-ey-1",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.effect_params.target_replicas == 3
	e.risk_score == 30
}

# 2. scale_out for enterprise-y with target_replicas=5 -- exactly at max, should succeed
test_scale_out_enterprise_y_at_max if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-ey-2",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
		"target_replicas": 5,
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.effect_params.target_replicas == 5
}

# 3. scale_out for enterprise-y with target_replicas=6 -- exceeds max_replicas=5, should deny
test_scale_out_enterprise_y_over_max if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-ey-3",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
		"target_replicas": 6,
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "deny"
}

# 4. scale_in with default target_replicas -- should default to 1
test_scale_in_default_replicas if {
	eval := evaluate_with_mocks({
		"action": "scale_in",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-si-def",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "scale_in"
	e.effect_params.target_replicas == 1
}

# 5. drain_node for enterprise-y -- NOT in allowed_actions, should deny
test_drain_node_enterprise_y_denied if {
	eval := evaluate_with_mocks({
		"action": "drain_node",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-ey-dn",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "deny"
	e.scope == "LOCAL"
}

# 6. config_update for enterprise-y -- IS in allowed_actions, should succeed
test_config_update_enterprise_y_allowed if {
	eval := evaluate_with_mocks({
		"action": "config_update",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-ey-cu",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "config_update"
	e.risk_score == 20
	e.cooldown_seconds == 60
	e.action_class == "NON_DISRUPTIVE"
}

# 7. scale_out with priority="high" -- should resolve to priority=2
test_scale_out_high_priority if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-pr-hi",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "high",
	})
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.priority == 2
}

# 8. scale_out with priority="medium" -- should resolve to priority=5
test_scale_out_medium_priority if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-pr-md",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "medium",
	})
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.priority == 5
}

# 9. scale_out with priority="low" -- should resolve to priority=10
test_scale_out_low_priority if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-pr-lo",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "low",
	})
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.priority == 10
}

# 10. config_update with config_payload -- payload should propagate to effect_params
test_config_update_with_payload if {
	eval := evaluate_with_mocks({
		"action": "config_update",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-cu-pl",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
		"config_payload": {"key": "maxConn", "value": "5000"},
	})
	e := eval.effects[0]
	e.effect_type == "config_update"
	e.effect_params.config_payload == {"key": "maxConn", "value": "5000"}
}

# 11. Deny for unauthorized action -- reason should contain tenant name
test_deny_shows_reason_for_unauthorized if {
	eval := evaluate_with_mocks({
		"action": "scale_in",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-reason-auth",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "deny"
	contains(e.effect_params.reason, "enterprise-y")
	contains(e.effect_params.reason, "scale_in")
}

# 12. Deny for unknown action -- reason should contain the action name
test_deny_shows_reason_for_unknown if {
	eval := evaluate_with_mocks({
		"action": "delete_cluster",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-reason-unk",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "deny"
	contains(e.effect_params.reason, "delete_cluster")
}

# 13. drain_node for enterprise-x -- verify action_class is DISRUPTIVE_UNBOUNDED
test_drain_node_enterprise_x_disruptive_unbounded if {
	eval := evaluate_with_mocks({
		"action": "drain_node",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-dn-class",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "drain_node"
	e.action_class == "DISRUPTIVE_UNBOUNDED"
}

# 14. scale_out -- verify scope is GLOBAL
test_scale_out_scope_is_global if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-so-scope",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "scale_out"
	e.scope == "GLOBAL"
}

# 15. notify -- verify risk_score is 0
test_notify_risk_is_zero if {
	eval := evaluate_with_mocks({
		"action": "notify",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-nt-risk",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	e.effect_type == "notify"
	e.risk_score == 0
}

# 16. Verify only 1 effect is produced per evaluation for single actions
test_multiple_effects_not_produced if {
	eval := evaluate_with_mocks({
		"action": "restart_workload",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-single",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	eval.effects[0].effect_type == "restart_workload"
}

# 17. Verify effect_key contains action:tenant:target_ref parts
test_scale_out_effect_key_format if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-key-fmt",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	e := eval.effects[0]
	# effect_key format: "action:tenant:<serialized target_ref>"
	startswith(e.effect_key, "scale_out:enterprise-x:")
	contains(e.effect_key, "cluster-1")
	contains(e.effect_key, "ns-1")
	contains(e.effect_key, "pod-1")
}

# 18. scale_in for enterprise-y -- NOT in allowed_actions, should deny
test_scale_in_enterprise_y_denied if {
	eval := evaluate_with_mocks({
		"action": "scale_in",
		"tenant_id": "enterprise-y",
		"incident_id": "inc-ey-si",
		"source": "test-source",
		"target_ref": {"cluster_id": "cluster-1", "namespace": "ns-1", "name": "pod-1"},
		"priority": "normal",
	})
	count(eval.effects) == 1
	e := eval.effects[0]
	e.effect_type == "deny"
	e.scope == "LOCAL"
}
