package mace.cnf.domain

import future.keywords.if

# ============================================
# CNF DOMAIN POLICY — Tests
# ============================================
# Tests mock cross-layer data using `with` statements:
#   - data.mace.platform.effect_routing
#   - data.mace.platform.effect_taxonomy
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

mock_taxonomy := {
	"scale_out":          {"base_risk": 30, "cooldown_seconds": 300, "action_class": "DISRUPTIVE_BOUNDED"},
	"scale_in":           {"base_risk": 50, "cooldown_seconds": 300, "action_class": "DISRUPTIVE_BOUNDED"},
	"restart_workload":   {"base_risk": 70, "cooldown_seconds": 600, "action_class": "DISRUPTIVE_UNBOUNDED"},
	"drain_node":         {"base_risk": 80, "cooldown_seconds": 900, "action_class": "DISRUPTIVE_UNBOUNDED"},
	"config_update":      {"base_risk": 20, "cooldown_seconds": 60,  "action_class": "NON_DISRUPTIVE"},
	"notify":             {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"deny":               {"base_risk": 10, "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
	"allow":              {"base_risk": 0,  "cooldown_seconds": 0,   "action_class": "NON_DISRUPTIVE"},
}

mock_priority_levels := {"critical": 200, "high": 100, "normal": 50, "low": 25}

mock_operator_limits := {
	"max_replicas_per_tenant": 20,
	"max_risk_score": 90,
	"bypass_priorities": ["critical"],
}

mock_tenants := {
	"enterprise-x": {
		"constraints": {
			"max_replicas": 10,
			"allowed_actions": ["scale_out", "scale_in", "config_update"],
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

evaluate_with_mocks(action_input) := result if {
	result := mace.cnf.domain.evaluate
		with input as action_input
		with data.mace.platform.effect_routing as mock_platform_routing
		with data.mace.platform.effect_taxonomy as mock_taxonomy
		with data.mace.platform.priority_levels as mock_priority_levels
		with data.mace.cnf.domain.effect_routing as mock_domain_routing
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
		"priority": "high",
	})
	e := eval.effects[0]
	e.effect_type == "restart_workload"
	e.scope == "GLOBAL"
	e.risk_score == 70
	e.action_class == "DISRUPTIVE_UNBOUNDED"
	e.priority == "high"
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
		"target_ref": "cluster-1/ns-1/node-1",
		"priority": "critical",
	})
	e := eval.effects[0]
	e.effect_type == "drain_node"
	e.scope == "GLOBAL"
	e.risk_score == 80
	e.priority == "critical"
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
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
		"target_ref": "cluster-1/ns-1/pod-1",
		"priority": "critical",
	})
	e := eval.effects[0]
	e.priority == "critical"
}

test_default_priority if {
	eval := evaluate_with_mocks({
		"action": "scale_out",
		"tenant_id": "enterprise-x",
		"incident_id": "inc-1",
		"source": "test-source",
		"target_ref": "cluster-1/ns-1/pod-1",
		"priority": "unknown_priority",
	})
	e := eval.effects[0]
	e.priority == "normal"
}
