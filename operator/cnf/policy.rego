package mace.cnf.operator

import future.keywords.if
import future.keywords.in

# ============================================
# CNF OPERATOR POLICY — Executor Role
# ============================================
# Package: mace.cnf.operator
# Bundle:  bundle-cnf-operator.tar.gz
#
# Takes dispatched effect context and decides SUCCEEDED/FAILED.
# Uses limits.json for thresholds:
#   - max_risk_score: risk score above this -> FAILED unless bypass priority
#   - bypass_priorities: priority levels that bypass risk check
#
# Tenant-specific overrides are NOT here (those are in tenant bundle).
#
# Output: { "status": "SUCCEEDED"|"FAILED", "reason", "effect_type" }

# -------------------------------------------
# Configuration from limits.json
# -------------------------------------------

max_risk_score := data.mace.cnf.operator.limits.max_risk_score

bypass_priorities := data.mace.cnf.operator.limits.bypass_priorities

# Effect types that always succeed regardless of risk
always_succeed_types := {"notify", "allow", "open_ticket"}

# -------------------------------------------
# Helpers
# -------------------------------------------

coalesce_num(val, fallback) := val if { is_number(val) }
coalesce_num(val, fallback) := fallback if { not is_number(val) }

coalesce_str(val, fallback) := val if { is_string(val) }
coalesce_str(val, fallback) := fallback if { not is_string(val) }

# Is this effect known to any routing?
exec_known_effect if {
	input.effect_type
	data.mace.platform.effect_routing[input.effect_type]
}

exec_known_effect if {
	input.effect_type
	data.mace.cnf.domain.effect_routing[input.effect_type]
}

# High risk check
exec_high_risk if {
	input.risk_score
	input.risk_score >= max_risk_score
}

# Bypass priority check
exec_bypass_priority if {
	input.priority
	input.priority in bypass_priorities
}

# Always-succeed effect type
exec_always_succeed if {
	input.effect_type
	input.effect_type in always_succeed_types
}

# -------------------------------------------
# EXECUTION DECISION
# -------------------------------------------

# High risk -> FAIL (unless bypass)
exec_status := "FAILED" if {
	exec_known_effect
	not exec_always_succeed
	exec_high_risk
	not exec_bypass_priority
}

# Critical priority bypasses risk
exec_status := "SUCCEEDED" if {
	exec_known_effect
	exec_high_risk
	exec_bypass_priority
}

# Always-succeed types
exec_status := "SUCCEEDED" if {
	exec_known_effect
	exec_always_succeed
}

# Unknown effect -> FAIL
exec_status := "FAILED" if {
	input.effect_type
	not exec_known_effect
}

# Default: succeed
exec_status := "SUCCEEDED" if {
	exec_known_effect
	not exec_high_risk
}

default exec_status := "SUCCEEDED"

# -------------------------------------------
# EXECUTION REASON
# -------------------------------------------

exec_reason := sprintf("Unknown effect type: %s — execution rejected", [coalesce_str(input.effect_type, "none")]) if {
	input.effect_type
	not exec_known_effect
}

exec_reason := sprintf("Risk score %d exceeds execution threshold %d — effect rejected", [
	input.risk_score, max_risk_score,
]) if {
	exec_known_effect
	not exec_always_succeed
	exec_high_risk
	not exec_bypass_priority
}

exec_reason := sprintf("Critical priority bypasses risk score %d for %s", [
	input.risk_score, input.effect_type,
]) if {
	exec_known_effect
	exec_high_risk
	exec_bypass_priority
}

exec_reason := sprintf("%s is a low-risk effect type — auto-succeed", [input.effect_type]) if {
	exec_known_effect
	exec_always_succeed
}

exec_reason := sprintf("Effect %s executed successfully (risk=%d, priority=%s)", [
	input.effect_type,
	coalesce_num(input.risk_score, 0),
	coalesce_str(input.priority, "normal"),
]) if {
	exec_known_effect
	not exec_high_risk
	not exec_always_succeed
}

default exec_reason := "Default execution — SUCCEEDED"

# -------------------------------------------
# EXECUTOR RESULT
# -------------------------------------------

execute := {
	"status": exec_status,
	"reason": exec_reason,
	"effect_type": coalesce_str(input.effect_type, "unknown"),
}
