package common.authz

# Haftasonu kontrolü (Global)
deny_weekend {
    # Simülasyon: Cumartesi/Pazar ise true döner
    # Gerçekte time.weekday() kullanılır, şimdilik manuel true/false yapabilirsin testi kolaylaştırmak için.
    false # Şimdilik kapalı, herkes geçsin
}