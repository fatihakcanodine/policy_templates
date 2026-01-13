package service_b.policy
import data.common.authz

default allow := false

allow if {
    not authz.deny_weekend
    input.group == "finance"
}