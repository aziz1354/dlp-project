rule CreditCardNumber {
    meta:
        description = "Detects credit card number patterns with format validation"
        author = "Your Name"
        date = "2023-10-XX"
    strings:
        // Visa: 16 digits starting with 4 (with optional formatting characters)
        $visa = /\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/
        
        // MasterCard: 16 digits starting with 51-55
        $mastercard = /\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/
        
        // American Express: 15 digits starting with 34 or 37
        $amex = /\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b/
        
        // Discover: 16 digits starting with 6011
        $discover = /\b6011[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/
    condition:
        any of them
}
