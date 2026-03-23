package mace.intent.evaluate

import future.keywords.if

# Default decision is REJECTED
default decision := "REJECTED"

# Valid action types
valid_action_types := {"SCALE_OUT", "SCALE_IN", "RESTART", "UPDATE_CONFIG"}

# Check if there are conflicting active intents
has_conflict if {
    count(input.activeIntents) > 0
}

# ESCALATED: Action type is DELETE
decision := "ESCALATED" if {
    input.intent.actionType == "DELETE"
}

reason := "Action type DELETE requires manual escalation" if {
    input.intent.actionType == "DELETE"
}

# DEFERRED: Has conflict with existing active intents
decision := "DEFERRED" if {
    input.intent.actionType != "DELETE"
    has_conflict
}

reason := "Intent deferred due to conflicting active intents" if {
    input.intent.actionType != "DELETE"
    has_conflict
}

# ACCEPTED: Valid action type AND no conflict
decision := "ACCEPTED" if {
    valid_action_types[input.intent.actionType]
    not has_conflict
}

reason := "Intent accepted for processing" if {
    valid_action_types[input.intent.actionType]
    not has_conflict
}

# REJECTED: Invalid action type (default case)
reason := "Invalid action type" if {
    not valid_action_types[input.intent.actionType]
    input.intent.actionType != "DELETE"
}

# Result object containing both decision and reason
result := {
    "decision": decision,
    "reason": reason
}
