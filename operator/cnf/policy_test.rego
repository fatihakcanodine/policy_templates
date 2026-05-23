package mace.cnf.operator

import future.keywords.if

# ============================================
# CNF OPERATOR POLICY — Executor Tests
# ============================================
# Tests mock cross-layer data using `with` statements:
#   - data.mace.cnf.operator.limits
#   - data.mace.platform.effect_routing
#   - data.mace.cnf.domain.effect_routing

# -------------------------------------------
# Mock data fixtures
# -------------------------------------------

mock_limits := {
	"max_replicas_per_tenant": 20,
	"max_risk_score": 90,
	"bypass_priorities": [1],
}

mock_platform_routing := {
	"notify":         {"executor": "obs",          "scope": "LOCAL"},
	"open_ticket":    {"executor": "itsm-manager", "scope": "GLOBAL"},
	"suppress_alarm": {"executor": "obs",          "scope": "GLOBAL"},
	"audit_flag":     {"executor": "obs",          "scope": "LOCAL"},
}

mock_domain_routing := {
	"scale_out":        {"executor": "cnf-manager", "scope": "GLOBAL"},
	"scale_in":         {"executor": "cnf-manager", "scope": "GLOBAL"},
	"restart_workload": {"executor": "cnf-manager", "scope": "GLOBAL"},
	"config_update":    {"executor": "cnf-manager", "scope": "GLOBAL"},
	"drain_node":       {"executor": "cnf-manager", "scope": "GLOBAL"},
}

# -------------------------------------------
# Helper: execute with full mock context
# -------------------------------------------

execute_with_mocks(effect_input) := result if {
	result := data.mace.cnf.operator.execute
		with input as effect_input
		with data.mace.cnf.operator.limits as mock_limits
		with data.mace.platform.effect_routing as mock_platform_routing
		with data.mace.cnf.domain.effect_routing as mock_domain_routing
}

# -------------------------------------------
# Normal Execution — SUCCEEDED
# -------------------------------------------

test_scale_out_succeeds if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 30,
	})
	result.status == "SUCCEEDED"
}

test_restart_workload_succeeds if {
	result := execute_with_mocks({
		"effect_type": "restart_workload",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 70,
	})
	result.status == "SUCCEEDED"
}

test_config_update_succeeds if {
	result := execute_with_mocks({
		"effect_type": "config_update",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 20,
	})
	result.status == "SUCCEEDED"
}

# -------------------------------------------
# Always-Succeed Types
# -------------------------------------------

test_notify_always_succeeds if {
	result := execute_with_mocks({
		"effect_type": "notify",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 0,
	})
	result.status == "SUCCEEDED"
}

test_allow_always_succeeds if {
	result := execute_with_mocks({
		"effect_type": "allow",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 0,
	})
	result.status == "SUCCEEDED"
}

# -------------------------------------------
# High Risk -> FAILED
# -------------------------------------------

test_high_risk_fails if {
	result := execute_with_mocks({
		"effect_type": "drain_node",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 95,
	})
	result.status == "FAILED"
}

test_boundary_risk_90_fails if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 90,
	})
	result.status == "FAILED"
}

test_risk_89_succeeds if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 89,
	})
	result.status == "SUCCEEDED"
}

# -------------------------------------------
# Critical Priority Bypass
# -------------------------------------------

test_critical_bypasses_risk if {
	result := execute_with_mocks({
		"effect_type": "drain_node",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": 1,
		"risk_score": 95,
	})
	result.status == "SUCCEEDED"
}

# -------------------------------------------
# Unknown Effect -> FAILED
# -------------------------------------------

test_unknown_effect_fails if {
	result := execute_with_mocks({
		"effect_type": "nonexistent_action",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 10,
	})
	result.status == "FAILED"
}

# -------------------------------------------
# No Risk Score -> SUCCEEDED
# -------------------------------------------

test_no_risk_score_succeeds if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
	})
	result.status == "SUCCEEDED"
}

# -------------------------------------------
# Output Structure
# -------------------------------------------

test_execute_has_required_fields if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 30,
	})
	result.status
	result.reason
	result.effect_type == "scale_out"
}

# -------------------------------------------
# Reason Messages
# -------------------------------------------

test_reason_for_high_risk if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 95,
	})
	result.status == "FAILED"
	contains(result.reason, "exceeds execution threshold")
}

test_reason_for_critical_bypass if {
	result := execute_with_mocks({
		"effect_type": "scale_out",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": 1,
		"risk_score": 95,
	})
	result.status == "SUCCEEDED"
	contains(result.reason, "Critical priority bypasses")
}

test_reason_for_always_succeed if {
	result := execute_with_mocks({
		"effect_type": "notify",
		"effect_key": "test-key",
		"tenant_id": "enterprise-x",
		"plan_id": "plan-1",
		"incident_id": "inc-1",
		"priority": "normal",
		"risk_score": 0,
	})
	result.status == "SUCCEEDED"
	contains(result.reason, "auto-succeed")
}
