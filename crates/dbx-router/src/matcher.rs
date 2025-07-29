use radix_trie::{Trie, TrieCommon};
use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

use dbx_config::{KeyRoutingRule, PatternType};
use dbx_core::DbxResult;

use crate::RouterError;

/// Key matcher for routing operations based on key patterns
pub struct KeyMatcher {
    /// Radix trie for prefix matching
    prefix_trie: Trie<String, RoutingTarget>,
    /// Fast lookup for exact matches
    exact_matches: HashMap<String, RoutingTarget>,
    /// Linear scan rules for complex patterns (glob, regex, suffix)
    complex_rules: Vec<CompiledRule>,
    /// Statistics
    stats: MatcherStats,
}

/// Routing target with priority and backend info
#[derive(Debug, Clone)]
struct RoutingTarget {
    backend: String,
    priority: u32,
    pattern: String,
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
        let mut prefix_trie = Trie::new();
        let mut exact_matches = HashMap::new();
        let mut complex_rules = Vec::new();
        let mut pattern_type_counts = HashMap::new();

        // Sort rules by priority (higher priority first) for consistent ordering
        let mut sorted_rules = rules;
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in sorted_rules {
            let count = pattern_type_counts
                .entry(rule.pattern_type.clone())
                .or_insert(0);
            *count += 1;

            let target = RoutingTarget {
                backend: rule.backend.clone(),
                priority: rule.priority,
                pattern: rule.pattern.clone(),
            };

            match rule.pattern_type {
                PatternType::Prefix => {
                    // Use radix trie for prefix patterns - O(log n) lookup
                    prefix_trie.insert(rule.pattern.clone(), target);
                }
                PatternType::Exact => {
                    // Use HashMap for exact matches - O(1) lookup
                    exact_matches.insert(rule.pattern.clone(), target);
                }
                PatternType::Suffix | PatternType::Glob | PatternType::Regex => {
                    // Use linear scan for complex patterns
                    let matcher = Self::compile_pattern(&rule.pattern, &rule.pattern_type)?;
                    complex_rules.push(CompiledRule {
                        pattern: rule.pattern.clone(),
                        backend: rule.backend.clone(),
                        priority: rule.priority,
                        pattern_type: rule.pattern_type.clone(),
                        matcher,
                    });
                }
            }
        }

        // Sort complex rules by priority for consistent priority handling
        complex_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        let stats = MatcherStats {
            total_rules: pattern_type_counts.values().sum(),
            exact_rules: exact_matches.len(),
            prefix_rules: prefix_trie.len(),
            complex_rules: complex_rules.len(),
            pattern_type_counts,
        };

        debug!(
            total_rules = stats.total_rules,
            prefix_rules = prefix_trie.len(),
            exact_rules = exact_matches.len(),
            complex_rules = complex_rules.len(),
            "Key matcher initialized"
        );

        Ok(Self {
            prefix_trie,
            exact_matches,
            complex_rules,
            stats,
        })
    }

    /// Match a key against routing rules
    pub fn match_key(&self, key: &str) -> Option<String> {
        // 1. Try exact match first - O(1)
        if let Some(target) = self.exact_matches.get(key) {
            debug!(
                key = %key,
                pattern = %target.pattern,
                backend = %target.backend,
                priority = target.priority,
                match_type = "exact",
                "Key matched routing rule"
            );
            return Some(target.backend.clone());
        }

        // 2. Try prefix match with radix trie - O(log n)
        if let Some(subtrie) = self.prefix_trie.get_ancestor(key) {
            if let Some((matched_prefix, target)) = subtrie.iter().next() {
                debug!(
                    key = %key,
                    pattern = %matched_prefix,
                    backend = %target.backend,
                    priority = target.priority,
                    match_type = "prefix",
                    "Key matched routing rule"
                );
                return Some(target.backend.clone());
            }
        }

        // 3. Try complex patterns (suffix, glob, regex) - O(k) where k is number of complex rules
        for rule in &self.complex_rules {
            if self.matches_pattern(&rule.matcher, key) {
                debug!(
                    key = %key,
                    pattern = %rule.pattern,
                    backend = %rule.backend,
                    priority = rule.priority,
                    match_type = ?rule.pattern_type,
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
        self.stats.clone()
    }

    /// Get detailed performance statistics
    pub fn get_performance_stats(&self) -> MatcherStats {
        MatcherStats {
            total_rules: self.stats.total_rules,
            exact_rules: self.exact_matches.len(),
            prefix_rules: self.prefix_trie.len(),
            complex_rules: self.complex_rules.len(),
            pattern_type_counts: self.stats.pattern_type_counts.clone(),
        }
    }

    /// Validate that all patterns are compilable
    pub fn validate_patterns(rules: &[KeyRoutingRule]) -> DbxResult<()> {
        for rule in rules {
            Self::compile_pattern(&rule.pattern, &rule.pattern_type)?;
        }
        Ok(())
    }

    /// Benchmark matcher performance
    pub fn benchmark_match(&self, key: &str, iterations: usize) -> BenchmarkResult {
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = self.match_key(key);
        }

        let duration = start.elapsed();

        BenchmarkResult {
            iterations,
            total_duration: duration,
            avg_duration_nanos: duration.as_nanos() as u64 / iterations as u64,
            operations_per_second: (iterations as f64 / duration.as_secs_f64()) as u64,
        }
    }
}

/// Performance statistics for matcher
#[derive(Debug, Clone)]
pub struct MatcherStats {
    pub total_rules: usize,
    pub exact_rules: usize,
    pub prefix_rules: usize,
    pub complex_rules: usize,
    pub pattern_type_counts: HashMap<PatternType, usize>,
}

/// Benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub iterations: usize,
    pub total_duration: std::time::Duration,
    pub avg_duration_nanos: u64,
    pub operations_per_second: u64,
}

/// Test result for a single rule
#[derive(Debug, Clone)]
pub struct TestResult {
    pub pattern: String,
    pub pattern_type: PatternType,
    pub backend: String,
    pub priority: u32,
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
                "Consider using direct pattern types (exact, prefix, suffix) where possible"
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
                suggestions.push(
                    "Consider breaking complex regex patterns into multiple rules".to_string(),
                );
            }
        }
    }

    fn patterns_may_overlap(
        pattern1: &str,
        type1: &PatternType,
        pattern2: &str,
        type2: &PatternType,
    ) -> bool {
        // Heuristic for potential overlaps
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
        // Heuristic for pattern subsumption
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
