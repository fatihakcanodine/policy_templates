package mace.intent.evaluate

import future.keywords.if

default decision := "REJECTED"

valid_action_types := {"SCALE_OUT", "SCALE_IN", "RESTART", "UPDATE_CONFIG"}

has_conflict if {
    count(input.activeIntents) > 0
}

# ESCALATED
decision := "ESCALATED" if {
    input.incomingIntent.actionType == "DELETE"
}

# DEFERRED
decision := "DEFERRED" if {
    input.incomingIntent.actionType != "DELETE"
    has_conflict
}

# ACCEPTED
decision := "ACCEPTED" if {
    valid_action_types[input.incomingIntent.actionType]
    not has_conflict
}

# Reasons...
reason := "Action type DELETE requires manual escalation" if {
    input.incomingIntent.actionType == "DELETE"
}

reason := "Intent deferred due to conflicting active intents" if {
    input.incomingIntent.actionType != "DELETE"
    has_conflict
}

reason := "Intent accepted for processing" if {
    valid_action_types[input.incomingIntent.actionType]
    not has_conflict
}

reason := "Invalid action type" if {
    not valid_action_types[input.incomingIntent.actionType]
    input.incomingIntent.actionType != "DELETE"
}

result := {
    "decision": decision,
    "reason": reason
}
