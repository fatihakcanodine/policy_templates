package service_b.policy
import data.common.authz

default allow = false

allow {
    not authz.deny_weekend
    
    # Servis B Özel Mantığı
    input.group == "finance"
}