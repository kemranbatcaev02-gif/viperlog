use std::borrow::Cow;
use aho_corasick::AhoCorasick;
use crate::engine::detector::{DetectorRegistry, MatchSpan};

pub struct ScrubScanner {
    detectors: DetectorRegistry,
    anchor_filter: AhoCorasick,
}

#[derive(Debug, Clone)]
pub struct ScanResult<'a> {
    pub cleaned_text: Cow<'a, str>,
    pub matches: Vec<MatchSpan>,
}

impl ScrubScanner {
    pub fn new() -> Self {
        let patterns = &[
            "@", "AKIA", "ghp_", "sk_live_", "sk_test_", "sk_mock_", "eyJ", "bearer", "Bearer",
            "password", "passwd", "secret", "api_key", "access_token",
            "4", "5", "3", "6",
        ];
        let anchor_filter = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("Failed to build AhoCorasick automaton");

        Self {
            detectors: DetectorRegistry::new(),
            anchor_filter,
        }
    }

    #[inline]
    pub fn might_contain_pii(&self, text: &str) -> bool {
        self.anchor_filter.is_match(text)
    }

    pub fn scrub_line<'a>(&self, line: &'a str) -> ScanResult<'a> {
        if !self.might_contain_pii(line) {
            return ScanResult {
                cleaned_text: Cow::Borrowed(line),
                matches: Vec::new(),
            };
        }

        let matches = self.detectors.find_matches(line);
        if matches.is_empty() {
            return ScanResult {
                cleaned_text: Cow::Borrowed(line),
                matches: Vec::new(),
            };
        }

        let mut result = String::with_capacity(line.len() + 32);
        let mut last_idx = 0;

        for m in &matches {
            if m.start > last_idx {
                result.push_str(&line[last_idx..m.start]);
            }
            result.push_str(&m.masked_value);
            last_idx = m.end;
        }

        if last_idx < line.len() {
            result.push_str(&line[last_idx..]);
        }

        ScanResult {
            cleaned_text: Cow::Owned(result),
            matches,
        }
    }

    pub fn audit_line(&self, line: &str) -> Vec<MatchSpan> {
        if !self.might_contain_pii(line) {
            return Vec::new();
        }
        self.detectors.find_matches(line)
    }
}

impl Default for ScrubScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_allocation_on_clean_line() {
        let scanner = ScrubScanner::new();
        let clean = "INFO [2026-10-27] Service started successfully on port 8080";
        let res = scanner.scrub_line(clean);

        match res.cleaned_text {
            Cow::Borrowed(b) => assert_eq!(b, clean),
            Cow::Owned(_) => panic!("Expected borrowed Cow for clean line"),
        }
        assert!(res.matches.is_empty());
    }

    #[test]
    fn test_credit_card_masking() {
        let scanner = ScrubScanner::new();
        let raw = "Payment processed for customer card 4242-4242-4242-4242 successfully.";
        let res = scanner.scrub_line(raw);

        assert_eq!(res.matches.len(), 1);
        assert_eq!(res.matches[0].pii_type, crate::engine::PiiType::CreditCard);
        assert_eq!(
            res.cleaned_text,
            "Payment processed for customer card ****-****-****-4242 successfully."
        );
    }

    #[test]
    fn test_aws_and_token_masking() {
        let scanner = ScrubScanner::new();
        let raw = "Connect to S3 using key AKIAIOSFODNN7EXAMPLE and secret sk_mock_abcdef1234567890abcdef12";
        let res = scanner.scrub_line(raw);

        assert_eq!(res.matches.len(), 2);
        assert!(res.cleaned_text.contains("AKIA****************"));
        assert!(res.cleaned_text.contains("sk_*****************************"));
    }

    #[test]
    fn test_email_and_ip_masking() {
        let scanner = ScrubScanner::new();
        let raw = "User alice@example.com logged in from 192.168.1.150 with status OK";
        let res = scanner.scrub_line(raw);

        assert_eq!(res.matches.len(), 2);
        assert!(res.cleaned_text.contains("a***e@example.com"));
    }
}
