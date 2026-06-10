package mace.platform

import future.keywords.if

# ============================================
# PLATFORM — Shared Helper Rules
# ============================================
# These rules are available to ALL bundles that load the platform layer.
# They provide common utilities for effect routing, risk scoring,
# and safe value coalescing.

# -------------------------------------------
# Effect Taxonomy — PLATFORM effects only
# -------------------------------------------
# Domain-specific effects (scale_out, restart_workload, etc.) are defined
# in each domain bundle's taxonomy.json. Use merge_taxonomy() to combine
# platform + domain taxonomies before lookups.

effect_taxonomy := {
	"notify":             {"base_risk": 0,  "cooldown_seconds": 0,    "action_class": "NON_DISRUPTIVE"},
	"deny":               {"base_risk": 10, "cooldown_seconds": 0,    "action_class": "NON_DISRUPTIVE"},
	"allow":              {"base_risk": 0,  "cooldown_seconds": 0,    "action_class": "NON_DISRUPTIVE"},
	"open_ticket":        {"base_risk": 5,  "cooldown_seconds": 0,    "action_class": "NON_DISRUPTIVE"},
	"suppress_alarm":     {"base_risk": 5,  "cooldown_seconds": 60,   "action_class": "NON_DISRUPTIVE"},
	"audit_flag":         {"base_risk": 0,  "cooldown_seconds": 0,    "action_class": "NON_DISRUPTIVE"},
}

# -------------------------------------------
# Merge taxonomy — domain overrides platform
# -------------------------------------------
# Usage: merge_taxonomy(data.mace.platform.effect_taxonomy, data.mace.cnf.domain.taxonomy)

merge_taxonomy(platform_tax, domain_tax) := merged if {
	merged := object.union(platform_tax, domain_tax)
}

# -------------------------------------------
# Priority Levels
# -------------------------------------------

priority_levels := {"critical": 1, "high": 2, "normal": 5, "medium": 5, "low": 10}

# -------------------------------------------
# Helpers: Resolve priority with fallback
# -------------------------------------------

get_priority(p) := priority_levels[lower_p] if {
	is_string(p)
	lower_p := lower(p)
	priority_levels[lower_p]
}

get_priority(p) := p if {
	is_number(p)
}

get_priority(p) := 5 if {
	is_string(p)
	lower_p := lower(p)
	not priority_levels[lower_p]
}

get_priority(p) := 5 if {
	not p
}

# -------------------------------------------
# Helpers: Coalesce utilities
# -------------------------------------------

coalesce_num(val, fallback) := val if { is_number(val) }
coalesce_num(val, fallback) := fallback if { not is_number(val) }

coalesce_str(val, fallback) := val if { is_string(val) }
coalesce_str(val, fallback) := fallback if { not is_string(val) }

coalesce_map(val, fallback) := val if { is_object(val) }
coalesce_map(val, fallback) := fallback if { not is_object(val) }

# -------------------------------------------
# Helpers: Merge routing tables
# -------------------------------------------
# Merges two effect routing maps (domain-specific overrides platform).

merge_routing(platform_routing, domain_routing) := merged if {
	merged := object.union(platform_routing, domain_routing)
}

# -------------------------------------------
# Helpers: Get effect config with fallback
# -------------------------------------------

get_effect_config(effect_type) := config if {
	config := effect_taxonomy[effect_type]
}

get_effect_config(effect_type) := {"base_risk": 0, "cooldown_seconds": 0, "action_class": "UNKNOWN"} if {
	not effect_taxonomy[effect_type]
}

# -------------------------------------------
# Helpers: Build effect key
# -------------------------------------------

build_effect_key(tenant_id, target_ref) := sprintf("%s:%s", [
	coalesce_str(tenant_id, "default"),
	coalesce_str(target_ref, "unknown"),
])
