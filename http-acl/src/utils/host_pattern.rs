//! Wildcard host pattern matching.
//!
//! Patterns are matched label-by-label (split on `.`), where a label is either a literal
//! (case-insensitive) or one of two wildcards:
//!
//! - `?` matches exactly one label (e.g. `?.example.com` matches `foo.example.com` but not
//!   `foo.bar.example.com` or `example.com`).
//! - `*` matches one or more labels (e.g. `*.example.com` matches `foo.example.com` and
//!   `foo.bar.example.com`, but not `example.com` itself).
//!
//! A wildcard must occupy an entire label - `foo*.example.com` is not a valid pattern.

use crate::utils::authority::is_valid_host;

/// A single label in a compiled [`HostPattern`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum HostPatternLabel {
    /// A literal, case-insensitive label.
    Literal(Box<str>),
    /// `?` - matches exactly one label.
    AnyOne,
    /// `*` - matches one or more labels.
    AnyOneOrMore,
}

/// A compiled wildcard host pattern (e.g. `*.example.com`, `?.example.com`).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct HostPattern(Box<[HostPatternLabel]>);

/// Returns true if `host` contains a `*` or `?` anywhere.
///
/// This is used to decide whether a host string should be treated as a literal
/// (exact-match) host or compiled as a wildcard pattern. It intentionally matches on
/// the character appearing *anywhere*, not just as a whole label: `*` is not a
/// forbidden host code point per the URL spec, so `foo*.example.com` would otherwise
/// silently pass through as a valid (but unmatchable) literal host instead of being
/// rejected by [`HostPattern::parse`] as the malformed pattern it looks like.
pub(crate) fn is_wildcard_host(host: &str) -> bool {
    host.contains(['*', '?'])
}

impl HostPattern {
    /// Parses a wildcard host pattern.
    ///
    /// Returns `None` if the pattern has no wildcard label, mixes wildcard characters
    /// into a literal label, or the literal labels don't form a valid host once the
    /// wildcard labels are substituted with a placeholder.
    pub(crate) fn parse(pattern: &str) -> Option<Self> {
        let mut labels = Vec::new();
        let mut reconstructed = Vec::new();
        let mut has_wildcard = false;

        for label in pattern.split('.') {
            match label {
                "*" => {
                    has_wildcard = true;
                    labels.push(HostPatternLabel::AnyOneOrMore);
                    reconstructed.push("w");
                }
                "?" => {
                    has_wildcard = true;
                    labels.push(HostPatternLabel::AnyOne);
                    reconstructed.push("w");
                }
                "" => return None,
                _ => {
                    if label.contains(['*', '?']) {
                        return None;
                    }
                    labels.push(HostPatternLabel::Literal(
                        label.to_ascii_lowercase().into_boxed_str(),
                    ));
                    reconstructed.push(label);
                }
            }
        }

        if !has_wildcard || !is_valid_host(&reconstructed.join(".")) {
            return None;
        }

        Some(Self(labels.into_boxed_slice()))
    }

    /// Returns whether `host` matches this pattern.
    pub(crate) fn matches(&self, host: &str) -> bool {
        let host_labels: Vec<&str> = host.split('.').collect();
        let n = host_labels.len();

        // dp[j] = whether the pattern prefix processed so far matches host_labels[..j].
        let mut dp = vec![false; n + 1];
        dp[0] = true;

        for label in self.0.iter() {
            let mut next = vec![false; n + 1];
            match label {
                HostPatternLabel::Literal(lit) => {
                    for j in 1..=n {
                        next[j] = dp[j - 1] && host_labels[j - 1].eq_ignore_ascii_case(lit);
                    }
                }
                HostPatternLabel::AnyOne => {
                    next[1..=n].copy_from_slice(&dp[..n]);
                }
                HostPatternLabel::AnyOneOrMore => {
                    for j in 1..=n {
                        next[j] = dp[j - 1] || next[j - 1];
                    }
                }
            }
            dp = next;
        }

        dp[n]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wildcard_host() {
        assert!(is_wildcard_host("*.example.com"));
        assert!(is_wildcard_host("?.example.com"));
        assert!(!is_wildcard_host("example.com"));
        // A `*`/`?` appearing anywhere routes to the pattern parser, even mid-label,
        // so that malformed patterns like this are rejected rather than silently
        // accepted as an unmatchable literal host.
        assert!(is_wildcard_host("fo*o.example.com"));
    }

    #[test]
    fn test_parse_rejects_non_wildcard() {
        assert!(HostPattern::parse("example.com").is_none());
    }

    #[test]
    fn test_parse_rejects_partial_wildcard_label() {
        assert!(HostPattern::parse("foo*.example.com").is_none());
        assert!(HostPattern::parse("foo?.example.com").is_none());
    }

    #[test]
    fn test_star_matches_one_or_more_labels() {
        let pattern = HostPattern::parse("*.example.com").unwrap();
        assert!(pattern.matches("foo.example.com"));
        assert!(pattern.matches("foo.bar.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("foo.example.org"));
    }

    #[test]
    fn test_question_mark_matches_exactly_one_label() {
        let pattern = HostPattern::parse("?.example.com").unwrap();
        assert!(pattern.matches("foo.example.com"));
        assert!(!pattern.matches("foo.bar.example.com"));
        assert!(!pattern.matches("example.com"));
    }

    #[test]
    fn test_case_insensitive_match() {
        let pattern = HostPattern::parse("*.Example.com").unwrap();
        assert!(pattern.matches("foo.EXAMPLE.COM"));
    }

    #[test]
    fn test_multiple_wildcards() {
        let pattern = HostPattern::parse("*.?.example.com").unwrap();
        assert!(pattern.matches("a.b.example.com"));
        assert!(pattern.matches("a.b.c.example.com"));
        assert!(!pattern.matches("b.example.com"));
    }
}
