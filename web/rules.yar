# Save as ~/rules.yar
rule CreditCardPattern {
    meta:
        description = "Detects potential credit card number pattern"
    strings:
        $cc = "4111111111111111"  // Simple exact match
    condition:
        $cc
}

rule SuspiciousExecutable {
    meta:
        description = "Detects Windows PE executables"
    strings:
        $MZ = { 4D 5A }
    condition:
        $MZ at 0
}
