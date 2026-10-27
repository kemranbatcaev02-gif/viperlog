pub fn validate_luhn(digits: &[u8]) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum: u32 = 0;
    let mut double = false;

    for &b in digits.iter().rev() {
        if !b.is_ascii_digit() {
            return false;
        }
        let mut val = (b - b'0') as u32;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }

    sum % 10 == 0
}

pub fn is_valid_credit_card(candidate: &str) -> bool {
    let mut digits = [0u8; 32];
    let mut count = 0;

    for &b in candidate.as_bytes() {
        if b.is_ascii_digit() {
            if count >= digits.len() {
                return false;
            }
            digits[count] = b;
            count += 1;
        } else if b != b'-' && b != b' ' {
            return false;
        }
    }

    validate_luhn(&digits[..count])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_luhn_cards() {
        assert!(is_valid_credit_card("4242-4242-4242-4242"));
        assert!(is_valid_credit_card("4242424242424242"));
        assert!(is_valid_credit_card("4111-1111-1111-1111"));
        assert!(is_valid_credit_card("4111 1111 1111 1111"));
    }

    #[test]
    fn test_invalid_cards() {
        assert!(!is_valid_credit_card("4532-0150-1234-5670"));
        assert!(!is_valid_credit_card("1234-5678-9012-3456"));
        assert!(!is_valid_credit_card("12345"));
        assert!(!is_valid_credit_card("phone: 555-019-2831"));
    }
}
