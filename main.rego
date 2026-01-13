package e2e.authz

default allow = false

allow {
    input.user == "superuser"
}