package mace.cnf.domain

import future.keywords.if
import future.keywords.in

# ============================================
# CNF DOMAIN POLICY — Producer Role
# ============================================
# Package: mace.cnf.domain
# Bundle:  bundle-cnf-domain.tar.gz
#
# Takes CorrelatedIncidentContext input and produces effects.
# Merges routing from:
#   - data.mace.platform.effect_routing (platform bundle)
#   - data.mace.cnf.domain.effect_routing (this bundle)
# Checks tenant constraints from:
#   - data.mace.cnf.tenants[input.tenant_id] (tenant bundle)
# Checks operator limits from:
#   - data.mace.cnf.operator.limits (operator bundle)
#
# For scale_out/scale_in: validates target_replicas against
# tenant max_replicas and operator max_replicas_per_tenant.
# For unknown/unauthorized actions -> deny effect (fail-closed).
#
# Output: { "effects": [...], "source", "tenant_id", "incident_id" }

# -------------------------------------------
# Resolved routing: platform + domain merged
# -------------------------------------------

resolved_routing := merged if {
	platform_routing := data.mace.platform.effect_routing
	domain_routing := data.mace.cnf.domain.effect_routing
	merged := object.union(platform_routing, domain_routing)
}

# -------------------------------------------
# Resolved tenant constraints
# -------------------------------------------

tenant_constraints := constraints if {
	input.tenant_id
	tenant_data := data.mace.cnf.tenants[input.tenant_id]
	constraints := tenant_data.constraints
}

tenant_constraints := {} if {
	not data.mace.cnf.tenants[input.tenant_id]
}

# -------------------------------------------
# Resolved operator limits
# -------------------------------------------

operator_limits := data.mace.cnf.operator.limits

# -------------------------------------------
# Helpers
# -------------------------------------------

get_priority := data.mace.platform.priority_levels[lower_prio] if {
	input.priority
	lower_prio := lower(input.priority)
	data.mace.platform.priority_levels[lower_prio]
}

get_priority := 5 if {
	not input.priority
}

get_priority := 5 if {
	input.priority
	lower_prio := lower(input.priority)
	not data.mace.platform.priority_levels[lower_prio]
}

get_priority := 5 if {
	not data.mace.platform.priority_levels
}

effect_scope(effect_type) := scope if {
	routing := resolved_routing[effect_type]
	scope := routing.scope
}

effect_scope(effect_type) := "LOCAL" if {
	not resolved_routing[effect_type]
}

get_effect_config(effect_type) := config if {
	config := data.mace.platform.effect_taxonomy[effect_type]
}

get_effect_config(effect_type) := {"base_risk": 0, "cooldown_seconds": 0, "action_class": "UNKNOWN"} if {
	not data.mace.platform.effect_taxonomy[effect_type]
}

coalesce_num(val, fallback) := val if { is_number(val) }
coalesce_num(val, fallback) := fallback if { not is_number(val) }

coalesce_str(val, fallback) := val if { is_string(val) }
coalesce_str(val, fallback) := fallback if { not is_string(val) }

coalesce_map(val, fallback) := val if { is_object(val) }
coalesce_map(val, fallback) := fallback if { not is_object(val) }

# -------------------------------------------
# Action authorization check
# -------------------------------------------

action_is_authorized if {
	tenant_constraints.allowed_actions
	input.action in tenant_constraints.allowed_actions
}

action_is_authorized if {
	not tenant_constraints.allowed_actions
}

# -------------------------------------------
# Replica limit validation
# -------------------------------------------

replica_within_limits(target) if {
	# Check tenant max_replicas
	tenant_max := tenant_constraints.max_replicas
	not tenant_max
	target <= operator_limits.max_replicas_per_tenant
}

replica_within_limits(target) if {
	# Check both tenant and operator limits
	tenant_max := tenant_constraints.max_replicas
	target <= tenant_max
	target <= operator_limits.max_replicas_per_tenant
}

replica_within_limits(target) if {
	# No tenant max, only operator limit
	not tenant_constraints.max_replicas
	target <= operator_limits.max_replicas_per_tenant
}

# -------------------------------------------
# EFFECT GENERATION
# -------------------------------------------

# SCALE_OUT
effect["scale_out"] := {
	"effect_type": "scale_out",
	"scope": effect_scope("scale_out"),
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": get_effect_config("scale_out").base_risk,
	"cooldown_seconds": get_effect_config("scale_out").cooldown_seconds,
	"action_class": get_effect_config("scale_out").action_class,
	"effect_params": {
		"target_replicas": object.get(input, "target_replicas", 3),
	},
} if {
	input.action == "scale_out"
	action_is_authorized
	replica_within_limits(object.get(input, "target_replicas", 3))
}

# SCALE_OUT — denied due to replica limits
effect["scale_out_denied_replicas"] := {
	"effect_type": "deny",
	"scope": "LOCAL",
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": "normal",
	"risk_score": 10,
	"cooldown_seconds": 0,
	"action_class": "NON_DISRUPTIVE",
	"effect_params": {
		"reason": sprintf("scale_out denied: target_replicas %d exceeds tenant or operator limits", [object.get(input, "target_replicas", 3)]),
	},
} if {
	input.action == "scale_out"
	action_is_authorized
	not replica_within_limits(object.get(input, "target_replicas", 3))
}

# SCALE_IN
effect["scale_in"] := {
	"effect_type": "scale_in",
	"scope": effect_scope("scale_in"),
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": get_effect_config("scale_in").base_risk,
	"cooldown_seconds": get_effect_config("scale_in").cooldown_seconds,
	"action_class": get_effect_config("scale_in").action_class,
	"effect_params": {
		"target_replicas": object.get(input, "target_replicas", 1),
	},
} if {
	input.action == "scale_in"
	action_is_authorized
	replica_within_limits(object.get(input, "target_replicas", 1))
}

# SCALE_IN — denied due to replica limits
effect["scale_in_denied_replicas"] := {
	"effect_type": "deny",
	"scope": "LOCAL",
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": "normal",
	"risk_score": 10,
	"cooldown_seconds": 0,
	"action_class": "NON_DISRUPTIVE",
	"effect_params": {
		"reason": sprintf("scale_in denied: target_replicas %d exceeds tenant or operator limits", [object.get(input, "target_replicas", 1)]),
	},
} if {
	input.action == "scale_in"
	action_is_authorized
	not replica_within_limits(object.get(input, "target_replicas", 1))
}

# RESTART_WORKLOAD
effect["restart_workload"] := {
	"effect_type": "restart_workload",
	"scope": effect_scope("restart_workload"),
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": get_effect_config("restart_workload").base_risk,
	"cooldown_seconds": get_effect_config("restart_workload").cooldown_seconds,
	"action_class": get_effect_config("restart_workload").action_class,
	"effect_params": {},
} if {
	input.action == "restart_workload"
	action_is_authorized
}

# DRAIN_NODE
effect["drain_node"] := {
	"effect_type": "drain_node",
	"scope": effect_scope("drain_node"),
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": get_effect_config("drain_node").base_risk,
	"cooldown_seconds": get_effect_config("drain_node").cooldown_seconds,
	"action_class": get_effect_config("drain_node").action_class,
	"effect_params": {},
} if {
	input.action == "drain_node"
	action_is_authorized
}

# CONFIG_UPDATE
effect["config_update"] := {
	"effect_type": "config_update",
	"scope": effect_scope("config_update"),
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": get_effect_config("config_update").base_risk,
	"cooldown_seconds": get_effect_config("config_update").cooldown_seconds,
	"action_class": get_effect_config("config_update").action_class,
	"effect_params": {
		"config_payload": object.get(input, "config_payload", {}),
	},
} if {
	input.action == "config_update"
	action_is_authorized
}

# NOTIFY — pass through (platform routing)
effect["notify"] := {
	"effect_type": "notify",
	"scope": effect_scope("notify"),
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": 0,
	"cooldown_seconds": 0,
	"action_class": "NON_DISRUPTIVE",
	"effect_params": {
		"message": sprintf("Notification for action %s on %s", [object.get(input, "action", "unknown"), object.get(input, "target_ref", "unknown")]),
	},
} if {
	input.action == "notify"
}

# ALLOW — pass through
effect["allow"] := {
	"effect_type": "allow",
	"scope": "LOCAL",
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": get_priority,
	"risk_score": 0,
	"cooldown_seconds": 0,
	"action_class": "NON_DISRUPTIVE",
	"effect_params": {},
} if {
	input.action == "allow"
}

# Action not authorized for this tenant -> deny
# Only applies to domain-managed actions (not platform pass-throughs like notify/allow)
effect["deny_unauthorized"] := {
	"effect_type": "deny",
	"scope": "LOCAL",
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": "normal",
	"risk_score": 10,
	"cooldown_seconds": 0,
	"action_class": "NON_DISRUPTIVE",
	"effect_params": {
		"reason": sprintf("Action %s not authorized for tenant %s", [input.action, object.get(input, "tenant_id", "unknown")]),
	},
} if {
	input.action
	data.mace.cnf.domain.effect_routing[input.action]
	tenant_constraints.allowed_actions
	not input.action in tenant_constraints.allowed_actions
}

# Unknown action -> deny (fail-closed)
effect["deny_unknown"] := {
	"effect_type": "deny",
	"scope": "LOCAL",
	"effect_key": sprintf("%s:%s", [object.get(input, "tenant_id", "default"), object.get(input, "target_ref", "unknown")]),
	"priority": "normal",
	"risk_score": 10,
	"cooldown_seconds": 0,
	"action_class": "NON_DISRUPTIVE",
	"effect_params": {
		"reason": sprintf("Unknown action: %s — fail-closed", [object.get(input, "action", "none")]),
	},
} if {
	input.action
	not resolved_routing[input.action]
}

# -------------------------------------------
# PRODUCER RESULT
# -------------------------------------------

effects := [e |
	some k
	e := effect[k]
]

evaluate := {
	"effects": effects,
	"source": object.get(input, "source", "unknown"),
	"tenant_id": object.get(input, "tenant_id", "default"),
	"incident_id": object.get(input, "incident_id", ""),
	"policy_revision": object.get(data.mace.cnf.domain.meta, "policy_revision", "unknown"),
}
