package mace.intent.evaluate

import future.keywords.if

test_accepted_no_conflict if {
    result.decision == "ACCEPTED" with input as {
        "incomingIntent": {"actionType": "SCALE_OUT"},
        "activeIntents": []
    }
    result.reason == "Intent accepted for processing" with input as {
        "incomingIntent": {"actionType": "SCALE_OUT"},
        "activeIntents": []
    }
}

test_deferred_with_conflict if {
    result.decision == "DEFERRED" with input as {
        "incomingIntent": {"actionType": "SCALE_OUT"},
        "activeIntents": [{"intentId": "intent-123", "actionType": "SCALE_IN"}]
    }
    result.reason == "Intent deferred due to conflicting active intents" with input as {
        "incomingIntent": {"actionType": "SCALE_OUT"},
        "activeIntents": [{"intentId": "intent-123", "actionType": "SCALE_IN"}]
    }
}

test_escalated_delete if {
    result.decision == "ESCALATED" with input as {
        "incomingIntent": {"actionType": "DELETE"},
        "activeIntents": []
    }
    result.reason == "Action type DELETE requires manual escalation" with input as {
        "incomingIntent": {"actionType": "DELETE"},
        "activeIntents": []
    }
}

test_rejected_invalid if {
    result.decision == "REJECTED" with input as {
        "incomingIntent": {"actionType": "INVALID"},
        "activeIntents": []
    }
    result.reason == "Invalid action type" with input as {
        "incomingIntent": {"actionType": "INVALID"},
        "activeIntents": []
    }
}
