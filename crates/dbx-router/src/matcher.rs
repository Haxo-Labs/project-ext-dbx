use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, warn};

use dbx_config::{KeyRoutingRule, PatternType};
use dbx_core::DbxResult;

use crate::RouterError;

/// Key matcher for routing operations based on key patterns
pub struct KeyMatcher {
    rules: Vec<CompiledRule>,
}

/// Compiled routing rule with pattern matcher
#[derive(Debug)]
struct CompiledRule {
    pattern: String,
    backend: String,
    priority: u32,
    pattern_type: PatternType,
    matcher: RuleMatcher,
}

/// Pattern matcher implementations
#[derive(Debug)]
enum RuleMatcher {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Glob(glob::Pattern),
    Regex(Regex),
}

impl KeyMatcher {
    /// Create a new key matcher from routing rules
    pub fn new(rules: Vec<KeyRoutingRule>) -> DbxResult<Self> {
        let mut compiled_rules = Vec::new();

        for rule in rules {
            let matcher = Self::compile_pattern(&rule.pattern, &rule.pattern_type)?;

            compiled_rules.push(CompiledRule {
                pattern: rule.pattern.clone(),
                backend: rule.backend.clone(),
                priority: rule.priority,
                pattern_type: rule.pattern_type.clone(),
                matcher,
            });
        }

        // Sort rules by priority (higher priority first)
        compiled_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        debug!(
            rules_count = compiled_rules.len(),
            "Key matcher initialized"
        );

        Ok(Self {
            rules: compiled_rules,
        })
    }

    /// Match a key against routing rules and return the backend name
    pub fn match_key(&self, key: &str) -> Option<String> {
        for rule in &self.rules {
            if self.matches_pattern(&rule.matcher, key) {
                debug!(
                    key = %key,
                    pattern = %rule.pattern,
                    backend = %rule.backend,
                    priority = rule.priority,
                    "Key matched routing rule"
                );
                return Some(rule.backend.clone());
            }
        }

        debug!(key = %key, "No routing rule matched key");
        None
    }

    /// Check if a key matches a specific pattern
    fn matches_pattern(&self, matcher: &RuleMatcher, key: &str) -> bool {
        match matcher {
            RuleMatcher::Exact(pattern) => key == pattern,
            RuleMatcher::Prefix(prefix) => key.starts_with(prefix),
            RuleMatcher::Suffix(suffix) => key.ends_with(suffix),
            RuleMatcher::Glob(pattern) => pattern.matches(key),
            RuleMatcher::Regex(regex) => regex.is_match(key),
        }
    }

    /// Compile a pattern string into a matcher
    fn compile_pattern(pattern: &str, pattern_type: &PatternType) -> DbxResult<RuleMatcher> {
        match pattern_type {
            PatternType::Exact => Ok(RuleMatcher::Exact(pattern.to_string())),
            PatternType::Prefix => Ok(RuleMatcher::Prefix(pattern.to_string())),
            PatternType::Suffix => Ok(RuleMatcher::Suffix(pattern.to_string())),
            PatternType::Glob => {
                let glob_pattern =
                    glob::Pattern::new(pattern).map_err(|e| RouterError::InvalidPattern {
                        pattern: pattern.to_string(),
                        pattern_type: "glob".to_string(),
                        error: e.to_string(),
                    })?;
                Ok(RuleMatcher::Glob(glob_pattern))
            }
            PatternType::Regex => {
                let regex = Regex::new(pattern).map_err(|e| RouterError::InvalidPattern {
                    pattern: pattern.to_string(),
                    pattern_type: "regex".to_string(),
                    error: e.to_string(),
                })?;
                Ok(RuleMatcher::Regex(regex))
            }
        }
    }

    /// Get statistics about the matcher
    pub fn get_stats(&self) -> MatcherStats {
        let mut pattern_type_counts = HashMap::new();

        for rule in &self.rules {
            let count = pattern_type_counts
                .entry(rule.pattern_type.clone())
                .or_insert(0);
            *count += 1;
        }

        MatcherStats {
            total_rules: self.rules.len(),
            pattern_type_counts,
        }
    }

    /// Validate that all patterns are compilable
    pub fn validate_patterns(rules: &[KeyRoutingRule]) -> DbxResult<()> {
        for rule in rules {
            Self::compile_pattern(&rule.pattern, &rule.pattern_type)?;
        }
        Ok(())
    }

    /// Test a key against all rules and return match details
    pub fn test_key(&self, key: &str) -> Vec<MatchResult> {
        let mut results = Vec::new();

        for rule in &self.rules {
            let matches = self.matches_pattern(&rule.matcher, key);
            results.push(MatchResult {
                pattern: rule.pattern.clone(),
                backend: rule.backend.clone(),
                priority: rule.priority,
                pattern_type: rule.pattern_type.clone(),
                matches,
            });
        }

        results
    }
}

/// Statistics about the key matcher
#[derive(Debug, Clone)]
pub struct MatcherStats {
    pub total_rules: usize,
    pub pattern_type_counts: HashMap<PatternType, usize>,
}

/// Result of testing a key against a rule
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub pattern: String,
    pub backend: String,
    pub priority: u32,
    pub pattern_type: PatternType,
    pub matches: bool,
}

/// Key routing analyzer for debugging and optimization
pub struct KeyRoutingAnalyzer;

impl KeyRoutingAnalyzer {
    /// Analyze routing rules for potential issues
    pub fn analyze_rules(rules: &[KeyRoutingRule]) -> AnalysisReport {
        let mut warnings = Vec::new();
        let mut suggestions = Vec::new();

        // Check for overlapping patterns
        Self::check_overlapping_patterns(rules, &mut warnings);

        // Check for unreachable rules
        Self::check_unreachable_rules(rules, &mut warnings);

        // Check for performance issues
        Self::check_performance_issues(rules, &mut warnings, &mut suggestions);

        AnalysisReport {
            warnings,
            suggestions,
        }
    }

    fn check_overlapping_patterns(rules: &[KeyRoutingRule], warnings: &mut Vec<String>) {
        for (i, rule1) in rules.iter().enumerate() {
            for (j, rule2) in rules.iter().enumerate() {
                if i != j && rule1.priority == rule2.priority {
                    // Rules with same priority might conflict
                    if Self::patterns_may_overlap(
                        &rule1.pattern,
                        &rule1.pattern_type,
                        &rule2.pattern,
                        &rule2.pattern_type,
                    ) {
                        warnings.push(format!(
                            "Potentially overlapping patterns '{}' and '{}' with same priority {}",
                            rule1.pattern, rule2.pattern, rule1.priority
                        ));
                    }
                }
            }
        }
    }

    fn check_unreachable_rules(rules: &[KeyRoutingRule], warnings: &mut Vec<String>) {
        let mut sorted_rules = rules.to_vec();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for (i, rule) in sorted_rules.iter().enumerate() {
            for higher_rule in &sorted_rules[..i] {
                if Self::pattern_subsumes(
                    &higher_rule.pattern,
                    &higher_rule.pattern_type,
                    &rule.pattern,
                    &rule.pattern_type,
                ) {
                    warnings.push(format!(
                        "Rule '{}' (priority {}) may be unreachable due to higher priority rule '{}' (priority {})",
                        rule.pattern, rule.priority, higher_rule.pattern, higher_rule.priority
                    ));
                }
            }
        }
    }

    fn check_performance_issues(
        rules: &[KeyRoutingRule],
        warnings: &mut Vec<String>,
        suggestions: &mut Vec<String>,
    ) {
        let regex_count = rules
            .iter()
            .filter(|r| matches!(r.pattern_type, PatternType::Regex))
            .count();
        let glob_count = rules
            .iter()
            .filter(|r| matches!(r.pattern_type, PatternType::Glob))
            .count();

        if regex_count > 10 {
            warnings.push(format!(
                "High number of regex patterns ({}): may impact performance",
                regex_count
            ));
            suggestions.push(
                "Consider using simpler pattern types (exact, prefix, suffix) where possible"
                    .to_string(),
            );
        }

        if glob_count > 20 {
            warnings.push(format!(
                "High number of glob patterns ({}): consider optimization",
                glob_count
            ));
        }

        // Check for very complex regex patterns
        for rule in rules {
            if matches!(rule.pattern_type, PatternType::Regex) && rule.pattern.len() > 100 {
                warnings.push(format!("Very complex regex pattern: '{}'", rule.pattern));
                suggestions.push("Consider simplifying complex regex patterns or breaking them into multiple simpler rules".to_string());
            }
        }
    }

    fn patterns_may_overlap(
        pattern1: &str,
        type1: &PatternType,
        pattern2: &str,
        type2: &PatternType,
    ) -> bool {
        // Simple heuristic for potential overlaps
        match (type1, type2) {
            (PatternType::Exact, PatternType::Exact) => pattern1 == pattern2,
            (PatternType::Prefix, PatternType::Prefix) => {
                pattern1.starts_with(pattern2) || pattern2.starts_with(pattern1)
            }
            (PatternType::Suffix, PatternType::Suffix) => {
                pattern1.ends_with(pattern2) || pattern2.ends_with(pattern1)
            }
            // For complex patterns, assume potential overlap
            _ => true,
        }
    }

    fn pattern_subsumes(
        pattern1: &str,
        type1: &PatternType,
        pattern2: &str,
        type2: &PatternType,
    ) -> bool {
        // Simple heuristic for pattern subsumption
        match (type1, type2) {
            (PatternType::Exact, PatternType::Exact) => pattern1 == pattern2,
            (PatternType::Prefix, PatternType::Prefix) => pattern2.starts_with(pattern1),
            (PatternType::Suffix, PatternType::Suffix) => pattern2.ends_with(pattern1),
            // For complex patterns, conservative assumption
            _ => false,
        }
    }
}

/// Analysis report for routing rules
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
}
