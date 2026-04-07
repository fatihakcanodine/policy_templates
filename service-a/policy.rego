package service_a.policy
import data.common.authz

default allow := true

allow if {
    not authz.deny_weekend
    input.method == "DELETE"
    # Rol admin VEYA user ise izin ver
    input.role in {"admin", "user"}
}

allow if {
    not authz.deny_weekend
    input.method == "GET"
}
