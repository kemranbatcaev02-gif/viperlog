use std::fmt;
use regex::Regex;
use crate::engine::luhn::is_valid_credit_card;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    CreditCard,
    AwsKey,
    GitHubToken,
    StripeKey,
    Jwt,
    BearerToken,
    PasswordSecret,
    Email,
    IPv4,
}

impl fmt::Display for PiiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PiiType::CreditCard => write!(f, "Credit Card"),
            PiiType::AwsKey => write!(f, "AWS Access Key"),
            PiiType::GitHubToken => write!(f, "GitHub Personal Token"),
            PiiType::StripeKey => write!(f, "Stripe API Secret"),
            PiiType::Jwt => write!(f, "JWT Token"),
            PiiType::BearerToken => write!(f, "Bearer Authorization Token"),
            PiiType::PasswordSecret => write!(f, "Exposed Password/Secret"),
            PiiType::Email => write!(f, "Email Address"),
            PiiType::IPv4 => write!(f, "IPv4 Address"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatchSpan {
    pub start: usize,
    pub end: usize,
    pub pii_type: PiiType,
    pub masked_value: String,
}

pub struct DetectorRegistry {
    card_regex: Regex,
    aws_regex: Regex,
    github_regex: Regex,
    stripe_regex: Regex,
    jwt_regex: Regex,
    bearer_regex: Regex,
    secret_regex: Regex,
    email_regex: Regex,
    ipv4_regex: Regex,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            card_regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(),
            aws_regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            github_regex: Regex::new(r"\bghp_[0-9a-zA-Z]{36}\b").unwrap(),
            stripe_regex: Regex::new(r"\bsk_(?:live|test|mock)_[0-9a-zA-Z]{20,}\b").unwrap(),
            jwt_regex: Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap(),
            bearer_regex: Regex::new(r"(?i)\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)").unwrap(),
            secret_regex: Regex::new(r#"(?i)(?:password|passwd|secret|api_key|access_token)\s*[:=]\s*["']?([^"',\s>]+)"#).unwrap(),
            email_regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            ipv4_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
        }
    }

    pub fn find_matches(&self, text: &str) -> Vec<MatchSpan> {
        let mut matches = Vec::new();

        for m in self.card_regex.find_iter(text) {
            let candidate = m.as_str();
            if is_valid_credit_card(candidate) {
                matches.push(MatchSpan {
                    start: m.start(),
                    end: m.end(),
                    pii_type: PiiType::CreditCard,
                    masked_value: mask_credit_card(candidate),
                });
            }
        }

        for m in self.aws_regex.find_iter(text) {
            matches.push(MatchSpan {
                start: m.start(),
                end: m.end(),
                pii_type: PiiType::AwsKey,
                masked_value: "AKIA****************".to_string(),
            });
        }

        for m in self.github_regex.find_iter(text) {
            matches.push(MatchSpan {
                start: m.start(),
                end: m.end(),
                pii_type: PiiType::GitHubToken,
                masked_value: "ghp_************************************".to_string(),
            });
        }

        for m in self.stripe_regex.find_iter(text) {
            matches.push(MatchSpan {
                start: m.start(),
                end: m.end(),
                pii_type: PiiType::StripeKey,
                masked_value: "sk_*****************************".to_string(),
            });
        }

        for m in self.jwt_regex.find_iter(text) {
            matches.push(MatchSpan {
                start: m.start(),
                end: m.end(),
                pii_type: PiiType::Jwt,
                masked_value: "[REDACTED_JWT_TOKEN]".to_string(),
            });
        }

        for cap in self.bearer_regex.captures_iter(text) {
            if let Some(token_match) = cap.get(1) {
                matches.push(MatchSpan {
                    start: token_match.start(),
                    end: token_match.end(),
                    pii_type: PiiType::BearerToken,
                    masked_value: "********".to_string(),
                });
            }
        }

        for cap in self.secret_regex.captures_iter(text) {
            if let Some(val_match) = cap.get(1) {
                let val = val_match.as_str();
                if val.len() > 3 && val != "null" && val != "true" && val != "false" {
                    matches.push(MatchSpan {
                        start: val_match.start(),
                        end: val_match.end(),
                        pii_type: PiiType::PasswordSecret,
                        masked_value: "********".to_string(),
                    });
                }
            }
        }

        for m in self.email_regex.find_iter(text) {
            matches.push(MatchSpan {
                start: m.start(),
                end: m.end(),
                pii_type: PiiType::Email,
                masked_value: mask_email(m.as_str()),
            });
        }

        for m in self.ipv4_regex.find_iter(text) {
            let ip = m.as_str();
            if ip != "127.0.0.1" && ip != "0.0.0.0" {
                matches.push(MatchSpan {
                    start: m.start(),
                    end: m.end(),
                    pii_type: PiiType::IPv4,
                    masked_value: mask_ip(ip),
                });
            }
        }

        matches.sort_by_key(|m| m.start);
        deduplicate_spans(matches)
    }
}

fn mask_credit_card(card: &str) -> String {
    let digits_only: Vec<char> = card.chars().filter(|c| c.is_ascii_digit()).collect();
    let last4: String = digits_only.iter().rev().take(4).rev().collect();

    if card.contains('-') {
        format!("****-****-****-{}", last4)
    } else if card.contains(' ') {
        format!("**** **** **** {}", last4)
    } else {
        format!("************{}", last4)
    }
}

fn mask_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return "[REDACTED_EMAIL]".to_string();
    }
    let username = parts[0];
    let domain = parts[1];

    if username.len() <= 2 {
        format!("*@{}", domain)
    } else {
        let first = username.chars().next().unwrap_or('*');
        let last = username.chars().last().unwrap_or('*');
        format!("{}***{}@{}", first, last, domain)
    }
}

fn mask_ip(ip: &str) -> String {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 {
        format!("{}.{}.***.*** ", octets[0], octets[1])
    } else {
        "[REDACTED_IP]".to_string()
    }
}

fn deduplicate_spans(spans: Vec<MatchSpan>) -> Vec<MatchSpan> {
    let mut result = Vec::with_capacity(spans.len());
    let mut last_end = 0;

    for span in spans {
        if span.start >= last_end {
            last_end = span.end;
            result.push(span);
        }
    }

    result
}
