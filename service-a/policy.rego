package service_a.policy
import data.common.authz # Ortak kuralı içeri al

default allow = false

allow {
    # 1. Önce Global kurala takılmadığından emin ol
    not authz.deny_weekend
    
    # 2. Servis A Özel Mantığı
    input.method == "DELETE"
    input.role == "admin"
}

allow {
    not authz.deny_weekend
    input.method == "GET" # Okumak serbest
}