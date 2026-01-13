package service_a.policy
import data.common.authz

default allow := false

allow if {
    not authz.deny_weekend
    input.method == "DELETE"
    input.role == "admin"
}

allow if {
    not authz.deny_weekend
    input.method == "GET"
}
