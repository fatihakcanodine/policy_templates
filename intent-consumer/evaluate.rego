package mace.intent.evaluate

import future.keywords.if

default decision := "REJECTED"

valid_action_types := {"SCALE_OUT", "SCALE_IN", "RESTART", "UPDATE_CONFIG"}

has_conflict if {
    count(input.activeIntents) > 0
}

# ESCALATED: DELETE action requires manual approval
decision := "ESCALATED" if {
    input.incomingIntent.actionType == "DELETE"
}

reason := "Action type DELETE requires manual escalation" if {
    input.incomingIntent.actionType == "DELETE"
}

# DEFERRED: Conflict with existing active intents
decision := "DEFERRED" if {
    input.incomingIntent.actionType != "DELETE"
    has_conflict
}

reason := "Intent deferred due to conflicting active intents" if {
    input.incomingIntent.actionType != "DELETE"
    has_conflict
}

# ACCEPTED: Valid action type, no conflict
decision := "ACCEPTED" if {
    valid_action_types[input.incomingIntent.actionType]
    not has_conflict
}

reason := "Intent accepted for processing" if {
    valid_action_types[input.incomingIntent.actionType]
    not has_conflict
}

# REJECTED: Invalid action type
reason := "Invalid action type" if {
    not valid_action_types[input.incomingIntent.actionType]
    input.incomingIntent.actionType != "DELETE"
}

result := {
    "decision": decision,
    "reason": reason
}
