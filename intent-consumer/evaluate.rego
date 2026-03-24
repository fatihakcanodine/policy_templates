package mace.intent.evaluate

import future.keywords.if

default decision := "REJECTED"

# ============================================
# CONFIGURATION
# ============================================

valid_action_types := {"SCALE_OUT", "SCALE_IN", "RESTART", "UPDATE_CONFIG"}

# Resource Limits
max_replicas := 10
min_replicas := 1

# Source Authorization Map
# Format: source -> allowed action types
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

# Get target_replicas from desiredState
target_replicas if {
    input.incomingIntent.desiredState.target_replicas
}

# Check if source is authorized for the action
source_authorized if {
    allowed := source_permissions[input.incomingIntent.source]
    allowed[input.incomingIntent.actionType]
}

# Check if source exists in permissions
known_source if {
    source_permissions[input.incomingIntent.source]
}

# Helper: replicas within limits or not specified
replicas_valid if {
    not target_replicas
}

replicas_valid if {
    target_replicas
    input.incomingIntent.desiredState.target_replicas >= min_replicas
    input.incomingIntent.desiredState.target_replicas <= max_replicas
}

# ============================================
# SCENARIO 1: RESOURCE LIMITS
# ============================================

# REJECTED: Replicas exceed maximum limit
decision := "REJECTED" if {
    valid_action_types[input.incomingIntent.actionType]
    target_replicas
    input.incomingIntent.desiredState.target_replicas > max_replicas
}

reason := sprintf("Replica count %d exceeds maximum limit of %d", [
    input.incomingIntent.desiredState.target_replicas,
    max_replicas
]) if {
    valid_action_types[input.incomingIntent.actionType]
    target_replicas
    input.incomingIntent.desiredState.target_replicas > max_replicas
}

# REJECTED: Replicas below minimum limit
decision := "REJECTED" if {
    valid_action_types[input.incomingIntent.actionType]
    target_replicas
    input.incomingIntent.desiredState.target_replicas < min_replicas
}

reason := sprintf("Replica count %d is below minimum limit of %d", [
    input.incomingIntent.desiredState.target_replicas,
    min_replicas
]) if {
    valid_action_types[input.incomingIntent.actionType]
    target_replicas
    input.incomingIntent.desiredState.target_replicas < min_replicas
}

# ============================================
# SCENARIO 2: SOURCE AUTHORIZATION
# ============================================

# REJECTED: Unknown source
decision := "REJECTED" if {
    not known_source
}

reason := sprintf("Unknown source '%s' is not authorized", [input.incomingIntent.source]) if {
    not known_source
}

# REJECTED: Source not authorized for this action
decision := "REJECTED" if {
    known_source
    not source_authorized
    input.incomingIntent.actionType != "DELETE"
}

reason := sprintf("Source '%s' is not authorized for action '%s'", [
    input.incomingIntent.source,
    input.incomingIntent.actionType
]) if {
    known_source
    not source_authorized
    input.incomingIntent.actionType != "DELETE"
}

# ============================================
# EXISTING RULES
# ============================================

# ESCALATED: DELETE action requires manual approval
decision := "ESCALATED" if {
    input.incomingIntent.actionType == "DELETE"
    source_authorized
}

reason := "Action type DELETE requires manual escalation" if {
    input.incomingIntent.actionType == "DELETE"
    source_authorized
}

# DEFERRED: Conflict with existing active intents
decision := "DEFERRED" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    replicas_valid
    has_conflict
}

reason := "Intent deferred due to conflicting active intents" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    replicas_valid
    has_conflict
}

# ACCEPTED: Valid action type, authorized source, no conflict, within limits
decision := "ACCEPTED" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    not has_conflict
    replicas_valid
}

reason := "Intent accepted for processing" if {
    valid_action_types[input.incomingIntent.actionType]
    source_authorized
    not has_conflict
    replicas_valid
}

# REJECTED: Invalid action type
reason := sprintf("Invalid action type '%s'", [input.incomingIntent.actionType]) if {
    not valid_action_types[input.incomingIntent.actionType]
    input.incomingIntent.actionType != "DELETE"
}

# ============================================
# RESULT
# ============================================

result := {
    "decision": decision,
    "reason": reason
}
