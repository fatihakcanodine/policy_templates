package mace.cnf.domain

import future.keywords.if
import future.keywords.in

# ============================================
# REACTIVE RULE EVALUATION — Event-Triggered
# ============================================
# Package: mace.cnf.domain (same as policy.rego)
# Bundle:  bundle-cnf-domain.tar.gz
#
# When input.event is present, evaluates event-driven reactive rules
# that can produce effects on CROSS-RESOURCE targets.
#
# Data sources:
#   - data.mace.cnf.domain.reactive_rules.rules (domain defaults)
#   - data.mace.cnf.tenants[input.tenant_id].reactive_rules.rules (tenant overrides)
#
# Safety:
#   - effect_type must be in tenant allowed_actions
#   - delta must respect tenant max_replicas and operator max_replicas_per_tenant
#   - effect_key uses "reactive:" prefix to avoid collision with request-driven

# -------------------------------------------
# Rule resolution: domain + tenant merge
# -------------------------------------------

# Domain base rules from data bundle
domain_reactive_rules := rules if {
	data.mace.cnf.domain.reactive_rules.rules
	rules := data.mace.cnf.domain.reactive_rules.rules
}

domain_reactive_rules := [] if {
	not data.mace.cnf.domain.reactive_rules
}

# Tenant override rules (optional)
tenant_reactive_rules := rules if {
	input.tenant_id
	tenant_data := data.mace.cnf.tenants[input.tenant_id]
	tenant_data.reactive_rules
	rules := tenant_data.reactive_rules.rules
}

tenant_reactive_rules := [] if {
	not input.tenant_id
}

tenant_reactive_rules := [] if {
	input.tenant_id
	not data.mace.cnf.tenants[input.tenant_id]
}

tenant_reactive_rules := [] if {
	input.tenant_id
	data.mace.cnf.tenants[input.tenant_id]
	not data.mace.cnf.tenants[input.tenant_id].reactive_rules
}

# Build override map keyed by rule id
tenant_override_map := {rule.id: rule |
	some rule in tenant_reactive_rules
	rule.id
}

# Merge: tenant overrides domain by id
resolved_reactive_rules := [merged |
	some domain_rule in domain_reactive_rules
	merged := object.union(domain_rule, object.get(tenant_override_map, domain_rule.id, {}))
]

# Filter to enabled rules only (enabled omitted defaults to true)
enabled_reactive_rules := [rule |
	some rule in resolved_reactive_rules
	object.get(rule, "enabled", true)
]

# -------------------------------------------
# Event extraction
# -------------------------------------------

event := input.event

# -------------------------------------------
# Condition evaluation helpers
# -------------------------------------------

condition_matches(cond, event_data) if {
	cond.operator == "eq"
	event_data[cond.field] == cond.value
}

condition_matches(cond, event_data) if {
	cond.operator == "neq"
	event_data[cond.field] != cond.value
}

condition_matches(cond, event_data) if {
	cond.operator == "gt"
	is_number(event_data[cond.field])
	is_number(cond.value)
	event_data[cond.field] > cond.value
}

condition_matches(cond, event_data) if {
	cond.operator == "gte"
	is_number(event_data[cond.field])
	is_number(cond.value)
	event_data[cond.field] >= cond.value
}

condition_matches(cond, event_data) if {
	cond.operator == "lt"
	is_number(event_data[cond.field])
	is_number(cond.value)
	event_data[cond.field] < cond.value
}

condition_matches(cond, event_data) if {
	cond.operator == "lte"
	is_number(event_data[cond.field])
	is_number(cond.value)
	event_data[cond.field] <= cond.value
}

# -------------------------------------------
# Event matching
# -------------------------------------------

rule_triggers(rule) if {
	trigger := rule.trigger
	event.kind == trigger.kind
	event.name == trigger.name
	event.reason == trigger.reason
	condition_matches(trigger.condition, event)
}

# -------------------------------------------
# Authorization for reactive effects
# -------------------------------------------

reactive_action_authorized(effect_type) if {
	tenant_constraints.allowed_actions
	effect_type in tenant_constraints.allowed_actions
}

reactive_action_authorized(effect_type) if {
	not tenant_constraints.allowed_actions
}

# -------------------------------------------
# Replica limit check for reactive scale effects
# -------------------------------------------
# Note: replica_within_limits() expects total target_replicas, not delta.
# For reactive rules we pass delta (incremental), so we check directly:
#   delta <= tenant max_replicas AND delta <= operator max_replicas_per_tenant

reactive_replica_within_limits(rule) if {
	rule.action.effect_type == "scale_out"
	delta := object.get(rule.action.params, "delta", 2)
	delta <= reactive_max_replica_limit
}

reactive_replica_within_limits(rule) if {
	rule.action.effect_type == "scale_in"
	delta := object.get(rule.action.params, "delta", 1)
	delta <= reactive_max_replica_limit
}

reactive_replica_within_limits(rule) if {
	rule.action.effect_type != "scale_out"
	rule.action.effect_type != "scale_in"
}

# Resolve the effective replica limit: min(tenant max_replicas, operator max_replicas_per_tenant)
reactive_max_replica_limit := min_limit if {
	tenant_max := object.get(tenant_constraints, "max_replicas", operator_limits.max_replicas_per_tenant)
	op_max := operator_limits.max_replicas_per_tenant
	min_limit := min_of(tenant_max, op_max)
}

# Fallback when no tenant constraints
reactive_max_replica_limit := operator_limits.max_replicas_per_tenant if {
	not tenant_constraints.max_replicas
}

# Min helper
min_of(a, b) := a if { a <= b }
min_of(a, b) := b if { b < a }

# -------------------------------------------
# REACTIVE EFFECT GENERATION
# -------------------------------------------

reactive_effect[rule.id] := {
		"effect_type": rule.action.effect_type,
		"scope": effect_scope(rule.action.effect_type),
		"effect_key": sprintf("reactive:%s:%s:%s", [
			rule.action.effect_type,
			object.get(input, "tenant_id", "default"),
			object.get(rule.action.target, "name", "unknown"),
		]),
		"priority": 5,
		"risk_score": get_effect_config(rule.action.effect_type).base_risk,
		"cooldown_seconds": get_effect_config(rule.action.effect_type).cooldown_seconds,
		"action_class": get_effect_config(rule.action.effect_type).action_class,
		"effect_params": {
			"target_replicas": object.get(rule.action.params, "delta", 2),
			"reactive_rule_id": rule.id,
			"trigger_event": event,
		},
		"target_ref": {
			"cluster_id": object.get(event, "cluster_id", ""),
			"namespace": object.get(event, "namespace", ""),
			"name": object.get(rule.action.target, "name", ""),
		},
	} if {
	some rule in enabled_reactive_rules
	rule_triggers(rule)
	reactive_action_authorized(rule.action.effect_type)
	reactive_replica_within_limits(rule)
}

# Denied: unauthorized effect type for this tenant
reactive_effect_denied[rule.id] := {
		"effect_type": "deny",
		"scope": "LOCAL",
		"effect_key": sprintf("reactive:deny:%s:%s", [
			object.get(input, "tenant_id", "default"),
			rule.id,
		]),
		"priority": 5,
		"risk_score": 10,
		"cooldown_seconds": 0,
		"action_class": "NON_DISRUPTIVE",
		"effect_params": {
			"reason": sprintf("Reactive rule %s denied: effect_type %s not authorized for tenant %s", [
				rule.id,
				rule.action.effect_type,
				object.get(input, "tenant_id", "unknown"),
			]),
			"reactive_rule_id": rule.id,
		},
	} if {
	some rule in enabled_reactive_rules
	rule_triggers(rule)
	not reactive_action_authorized(rule.action.effect_type)
}

# Denied: replica limit exceeded
reactive_effect_denied_replicas[rule.id] := {
		"effect_type": "deny",
		"scope": "LOCAL",
		"effect_key": sprintf("reactive:deny-replicas:%s:%s", [
			object.get(input, "tenant_id", "default"),
			rule.id,
		]),
		"priority": 5,
		"risk_score": 10,
		"cooldown_seconds": 0,
		"action_class": "NON_DISRUPTIVE",
		"effect_params": {
			"reason": sprintf("Reactive rule %s denied: delta exceeds tenant/operator replica limits", [rule.id]),
			"reactive_rule_id": rule.id,
		},
	} if {
	some rule in enabled_reactive_rules
	rule_triggers(rule)
	reactive_action_authorized(rule.action.effect_type)
	not reactive_replica_within_limits(rule)
}

# -------------------------------------------
# Reactive effects collection
# -------------------------------------------

reactive_effects := array.concat(
	[e | some k; e := reactive_effect[k]],
	array.concat(
		[e | some k; e := reactive_effect_denied[k]],
		[e | some k; e := reactive_effect_denied_replicas[k]],
	),
)

# -------------------------------------------
# REACTIVE EVALUATE — output shape matches policy.rego evaluate
# -------------------------------------------

reactive_evaluate := {
	"effects": reactive_effects,
	"source": "reactive-evaluator",
	"tenant_id": object.get(input, "tenant_id", "default"),
	"incident_id": object.get(input, "incident_id", ""),
	"policy_revision": object.get(data.mace.cnf.domain.meta, "policy_revision", "unknown"),
}
