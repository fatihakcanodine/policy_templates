package mace.intent.evaluate

import future.keywords.if

# ============================================
# CONFIGURATION
# ============================================

valid_action_types := {"SCALE_OUT", "SCALE_IN", "RESTART", "UPDATE_CONFIG"}

# Resource Limits
max_replicas := 10
min_replicas := 1

# Source Authorization Map
source_permissions := {
    "AI_AGENT": {"SCALE_OUT", "SCALE_IN"},
    "ADMIN_USER": {"SCALE_OUT", "SCALE_IN", "RESTART", "UPDATE_CONFIG", "DELETE"},
    "AUTO_SCALER": {"SCALE_IN"},
    "USER_UI": {"SCALE_OUT", "SCALE_IN", "RESTART"},
}

# ============================================
# HELPER FUNCTIONS
# ============================================

has_conflict if {
    count(input.activeIntents) > 0
}

target_replicas if {
    input.incomingIntent.desiredState.target_replicas
}

source_authorized if {
    allowed := source_permissions[input.incomingIntent.source]
    allowed[input.incomingIntent.actionType]
}

known_source if {
    source_permissions[input.incomingIntent.source]
}

replicas_within_limits if {
    not target_replicas
}

replicas_within_limits if {
    target_replicas
    input.incomingIntent.desiredState.target_replicas >= min_replicas
    input.incomingIntent.desiredState.target_replicas <= max_replicas
}

replicas_exceed_max if {
    target_replicas
    input.incomingIntent.desiredState.target_replicas > max_replicas
}

replicas_below_min if {
    target_replicas
    input.incomingIntent.desiredState.target_replicas < min_replicas
}

# ============================================
# DECISION LOGIC (Single Rule)
# ============================================

decision := "REJECTED" if {
    replicas_exceed_max
}

decision := "REJECTED" if {
    replicas_below_min
}

decision := "REJECTED" if {
    not known_source
}

decision := "REJECTED" if {
    known_source
    not source_authorized
    input.incomingIntent.actionType != "DELETE"
}

decision := "REJECTED" if {
    not valid_action_types[input.incomingIntent.actionType]
    input.incomingIntent.actionType != "DELETE"
}

decision := "ESCALATED" if {
    input.incomingIntent.actionType == "DELETE"
    source_authorized
}

decision := "DEFERRED" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    replicas_within_limits
    has_conflict
}

decision := "ACCEPTED" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    replicas_within_limits
    not has_conflict
}

# ============================================
# REASON LOGIC
# ============================================

reason := sprintf("Replica count %d exceeds maximum limit of %d", [
    input.incomingIntent.desiredState.target_replicas,
    max_replicas
]) if {
    replicas_exceed_max
}

reason := sprintf("Replica count %d is below minimum limit of %d", [
    input.incomingIntent.desiredState.target_replicas,
    min_replicas
]) if {
    replicas_below_min
}

reason := sprintf("Unknown source '%s' is not authorized", [input.incomingIntent.source]) if {
    not known_source
    not replicas_exceed_max
    not replicas_below_min
}

reason := sprintf("Source '%s' is not authorized for action '%s'", [
    input.incomingIntent.source,
    input.incomingIntent.actionType
]) if {
    known_source
    not source_authorized
    input.incomingIntent.actionType != "DELETE"
    not replicas_exceed_max
    not replicas_below_min
}

reason := sprintf("Invalid action type '%s'", [input.incomingIntent.actionType]) if {
    not valid_action_types[input.incomingIntent.actionType]
    input.incomingIntent.actionType != "DELETE"
    not replicas_exceed_max
    not replicas_below_min
    known_source
}

reason := "Action type DELETE requires manual escalation" if {
    input.incomingIntent.actionType == "DELETE"
    source_authorized
}

reason := "Intent deferred due to conflicting active intents" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    replicas_within_limits
    has_conflict
}

reason := "Intent accepted for processing" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    replicas_within_limits
    not has_conflict
}

# ============================================
# RESULT
# ============================================

result := {
    "decision": decision,
    "reason": reason
}
