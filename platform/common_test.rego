package mace.platform

import future.keywords.if

# ============================================
# PLATFORM — Shared Helper Tests
# ============================================

# --- Effect Taxonomy ---
test_effect_taxonomy_scale_out if {
	config := effect_taxonomy["scale_out"]
	config.base_risk == 30
	config.cooldown_seconds == 300
	config.action_class == "DISRUPTIVE_BOUNDED"
}

test_effect_taxonomy_notify if {
	config := effect_taxonomy["notify"]
	config.base_risk == 0
	config.cooldown_seconds == 0
	config.action_class == "NON_DISRUPTIVE"
}

test_effect_taxonomy_deny if {
	config := effect_taxonomy["deny"]
	config.base_risk == 10
	config.action_class == "NON_DISRUPTIVE"
}

test_effect_taxonomy_allow if {
	config := effect_taxonomy["allow"]
	config.base_risk == 0
	config.action_class == "NON_DISRUPTIVE"
}

# --- Priority Levels ---
test_get_priority_valid if {
	get_priority("critical") == "critical"
	get_priority("normal") == "normal"
}

test_get_priority_invalid_falls_back if {
	get_priority("unknown") == "normal"
}

test_priority_levels_values if {
	priority_levels["critical"] == 200
	priority_levels["high"] == 100
	priority_levels["normal"] == 50
	priority_levels["low"] == 25
}

# --- Coalesce Helpers ---
test_coalesce_num_with_value if {
	coalesce_num(42, 0) == 42
}

test_coalesce_num_with_null if {
	coalesce_num(null, 99) == 99
}

test_coalesce_str_with_value if {
	coalesce_str("hello", "default") == "hello"
}

test_coalesce_str_with_null if {
	coalesce_str(null, "fallback") == "fallback"
}

test_coalesce_map_with_value if {
	obj := {"a": 1}
	result := coalesce_map(obj, {})
	result.a == 1
}

test_coalesce_map_with_null if {
	result := coalesce_map(null, {"b": 2})
	result.b == 2
}

# --- Get Effect Config ---
test_get_effect_config_known if {
	config := get_effect_config("scale_out")
	config.base_risk == 30
}

test_get_effect_config_unknown if {
	config := get_effect_config("nonexistent_action")
	config.base_risk == 0
	config.action_class == "UNKNOWN"
}

# --- Merge Routing ---
test_merge_routing if {
	platform_routing := {"notify": {"executor": "obs", "scope": "LOCAL"}}
	domain_routing := {"scale_out": {"executor": "cnf-manager", "scope": "GLOBAL"}}
	merged := merge_routing(platform_routing, domain_routing)
	merged["notify"].executor == "obs"
	merged["scale_out"].executor == "cnf-manager"
}

test_merge_routing_domain_overrides if {
	platform_routing := {"notify": {"executor": "obs", "scope": "LOCAL"}}
	domain_routing := {"notify": {"executor": "custom", "scope": "GLOBAL"}}
	merged := merge_routing(platform_routing, domain_routing)
	merged["notify"].executor == "custom"
	merged["notify"].scope == "GLOBAL"
}

# --- Build Effect Key ---
test_build_effect_key if {
	key := build_effect_key("tenant-1", "cluster-1/ns-1/pod-1")
	key == "tenant-1:cluster-1/ns-1/pod-1"
}

test_build_effect_key_defaults if {
	key := build_effect_key(null, null)
	key == "default:unknown"
}
