package mace.intent.evaluate

import future.keywords.if

# Test 1: ACCEPTED - SCALE_OUT with empty activeIntents
test_accepted_no_conflict if {
    result with input as {
        "intent": {"actionType": "SCALE_OUT"},
        "activeIntents": []
    }
    result.decision == "ACCEPTED" with input as {
        "intent": {"actionType": "SCALE_OUT"},
        "activeIntents": []
    }
    result.reason == "Intent accepted for processing" with input as {
        "intent": {"actionType": "SCALE_OUT"},
        "activeIntents": []
    }
}

# Test 2: DEFERRED - SCALE_OUT with existing intent (conflict)
test_deferred_with_conflict if {
    result with input as {
        "intent": {"actionType": "SCALE_OUT"},
        "activeIntents": [{"intentId": "intent-123", "actionType": "SCALE_OUT"}]
    }
    result.decision == "DEFERRED" with input as {
        "intent": {"actionType": "SCALE_OUT"},
        "activeIntents": [{"intentId": "intent-123", "actionType": "SCALE_OUT"}]
    }
    result.reason == "Intent deferred due to conflicting active intents" with input as {
        "intent": {"actionType": "SCALE_OUT"},
        "activeIntents": [{"intentId": "intent-123", "actionType": "SCALE_OUT"}]
    }
}

# Test 3: ESCALATED - DELETE action
test_escalated_delete if {
    result with input as {
        "intent": {"actionType": "DELETE"},
        "activeIntents": []
    }
    result.decision == "ESCALATED" with input as {
        "intent": {"actionType": "DELETE"},
        "activeIntents": []
    }
    result.reason == "Action type DELETE requires manual escalation" with input as {
        "intent": {"actionType": "DELETE"},
        "activeIntents": []
    }
}

# Test 4: REJECTED - Invalid action type
test_rejected_invalid if {
    result with input as {
        "intent": {"actionType": "INVALID"},
        "activeIntents": []
    }
    result.decision == "REJECTED" with input as {
        "intent": {"actionType": "INVALID"},
        "activeIntents": []
    }
    result.reason == "Invalid action type" with input as {
        "intent": {"actionType": "INVALID"},
        "activeIntents": []
    }
}
