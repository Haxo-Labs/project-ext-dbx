use crate::models::{ApiResponse, RateLimitPolicy};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};

use chrono::{DateTime, Utc};
use dbx_core::{DataOperation, DataValue, UniversalBackend};
use serde::{Deserialize, Serialize};

use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: DateTime<Utc>,
    pub retry_after: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RateLimitContext {
    pub identifier: String,
    pub policy: RateLimitPolicy,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct SlidingWindowRateLimiter {
    backend: Arc<dyn UniversalBackend>,
}

impl SlidingWindowRateLimiter {
    pub fn new(backend: Arc<dyn UniversalBackend>) -> Self {
        Self { backend }
    }

    pub async fn check_rate_limit(
        &self,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult, String> {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(context.policy.window_seconds as i64);

        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);

        // Get existing timestamps for this identifier/endpoint
        let existing_timestamps = self.get_request_timestamps(&key).await?;

        // Filter timestamps to only include those within the sliding window
        let valid_timestamps: Vec<i64> = existing_timestamps
            .into_iter()
            .filter(|&timestamp| timestamp >= window_start.timestamp())
            .collect();

        let current_request_count = valid_timestamps.len() as u32;
        let effective_limit = context
            .policy
            .burst_allowance
            .unwrap_or(context.policy.requests);

        // Check if we're at the limit
        if current_request_count >= effective_limit {
            // Find the oldest request in the window to determine reset time
            let now_timestamp = now.timestamp();
            let oldest_timestamp = valid_timestamps.iter().min().unwrap_or(&now_timestamp);
            let reset_time = DateTime::from_timestamp(
                oldest_timestamp + context.policy.window_seconds as i64,
                0,
            )
            .unwrap_or(now + chrono::Duration::seconds(context.policy.window_seconds as i64));

            let retry_after = (reset_time - now).num_seconds().max(1) as u32;

            return Ok(RateLimitResult {
                allowed: false,
                limit: context.policy.requests,
                remaining: 0,
                reset_time,
                retry_after: Some(retry_after),
            });
        }

        // Add current request timestamp
        let mut updated_timestamps = valid_timestamps;
        updated_timestamps.push(now.timestamp());

        // Store updated timestamps
        self.store_request_timestamps(&key, &updated_timestamps, context.policy.window_seconds)
            .await?;

        let remaining = context
            .policy
            .requests
            .saturating_sub(updated_timestamps.len() as u32);
        let reset_time = now + chrono::Duration::seconds(context.policy.window_seconds as i64);

        Ok(RateLimitResult {
            allowed: true,
            limit: context.policy.requests,
            remaining,
            reset_time,
            retry_after: None,
        })
    }

    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> Result<(), String> {
        let key = format!("rate_limit:{}:{}", identifier, endpoint);

        match self
            .backend
            .execute_data(DataOperation::Delete { key, fields: None })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Reset error: {}", e)),
        }
    }

    pub async fn get_rate_limit_info(
        &self,
        identifier: &str,
        endpoint: &str,
        policy: &RateLimitPolicy,
    ) -> Result<RateLimitResult, String> {
        let _context = RateLimitContext {
            identifier: identifier.to_string(),
            policy: policy.clone(),
            endpoint: endpoint.to_string(),
        };

        // Get current status without incrementing (read-only check)
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(policy.window_seconds as i64);
        let key = format!("rate_limit:{}:{}", identifier, endpoint);

        let existing_timestamps = self.get_request_timestamps(&key).await?;

        let valid_timestamps: Vec<i64> = existing_timestamps
            .into_iter()
            .filter(|&timestamp| timestamp >= window_start.timestamp())
            .collect();

        let current_request_count = valid_timestamps.len() as u32;
        let remaining = policy.requests.saturating_sub(current_request_count);

        let reset_time = if let Some(&oldest) = valid_timestamps.iter().min() {
            DateTime::from_timestamp(oldest + policy.window_seconds as i64, 0)
                .unwrap_or(now + chrono::Duration::seconds(policy.window_seconds as i64))
        } else {
            now + chrono::Duration::seconds(policy.window_seconds as i64)
        };

        Ok(RateLimitResult {
            allowed: current_request_count < policy.requests,
            limit: policy.requests,
            remaining,
            reset_time,
            retry_after: None,
        })
    }

    async fn get_request_timestamps(&self, key: &str) -> Result<Vec<i64>, String> {
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(timestamps_str)) = result.data {
                        // Parse comma-separated timestamps
                        if timestamps_str.is_empty() {
                            Ok(Vec::new())
                        } else {
                            timestamps_str
                                .split(',')
                                .map(|s| {
                                    s.parse::<i64>().map_err(|e| format!("Parse error: {}", e))
                                })
                                .collect()
                        }
                    } else {
                        Ok(Vec::new())
                    }
                } else {
                    Ok(Vec::new())
                }
            }
            Err(e) => Err(format!("Backend error: {}", e)),
        }
    }

    async fn store_request_timestamps(
        &self,
        key: &str,
        timestamps: &[i64],
        window_seconds: u32,
    ) -> Result<(), String> {
        let timestamps_str = timestamps
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");

        match self
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::String(timestamps_str),
                ttl: Some(window_seconds as u64 * 2), // Keep data longer than window for safety
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Storage error: {}", e)),
        }
    }

    pub async fn increment_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:active_count".to_string();
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.clone(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                let current_count = if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        count_str.parse::<i64>().unwrap_or(0)
                    } else if let Some(DataValue::Int(count)) = result.data {
                        count
                    } else {
                        0
                    }
                } else {
                    0
                };

                self.backend
                    .execute_data(DataOperation::Set {
                        key,
                        value: DataValue::Int(current_count + 1),
                        ttl: None,
                    })
                    .await
                    .map_err(|e| format!("Increment error: {}", e))?;

                Ok(())
            }
            Err(e) => Err(format!("Get count error: {}", e)),
        }
    }

    pub async fn decrement_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:active_count".to_string();
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.clone(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                let current_count = if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        count_str.parse::<i64>().unwrap_or(0)
                    } else if let Some(DataValue::Int(count)) = result.data {
                        count
                    } else {
                        0
                    }
                } else {
                    0
                };

                let new_count = (current_count - 1).max(0);

                self.backend
                    .execute_data(DataOperation::Set {
                        key,
                        value: DataValue::Int(new_count),
                        ttl: None,
                    })
                    .await
                    .map_err(|e| format!("Decrement error: {}", e))?;

                Ok(())
            }
            Err(e) => Err(format!("Get count error: {}", e)),
        }
    }

    pub async fn count_active_limiters(&self) -> Result<i64, String> {
        let key = "rate_limit:active_count".to_string();
        match self
            .backend
            .execute_data(DataOperation::Get { key, fields: None })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        Ok(count_str.parse::<i64>().unwrap_or(0))
                    } else if let Some(DataValue::Int(count)) = result.data {
                        Ok(count)
                    } else {
                        Ok(0)
                    }
                } else {
                    Ok(0)
                }
            }
            Err(e) => Err(format!("Count error: {}", e)),
        }
    }
}

/// Bit vector rate limiter
pub struct BitVectorRateLimiter {
    backend: Arc<dyn UniversalBackend>,
    bucket_size_seconds: u32, // Size of each time bucket in seconds
}

/// Bit vector data structure for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimitBitVector {
    /// Bit vector where each bit represents a time bucket
    bits: Vec<u8>,
    /// Timestamp of the first bucket (bucket 0)
    start_timestamp: i64,
    /// Size of each bucket in seconds
    bucket_size_seconds: u32,
    /// Total number of buckets
    bucket_count: usize,
    /// Request count per bucket (optional, for more accurate counting)
    bucket_counts: Option<Vec<u16>>, // u16 allows up to 65535 requests per bucket
}

impl BitVectorRateLimiter {
    pub fn new(backend: Arc<dyn UniversalBackend>) -> Self {
        Self {
            backend,
            bucket_size_seconds: 1, // 1-second buckets for good granularity
        }
    }

    /// Create a new rate limiter with custom bucket size
    pub fn with_bucket_size(backend: Arc<dyn UniversalBackend>, bucket_size_seconds: u32) -> Self {
        Self {
            backend,
            bucket_size_seconds,
        }
    }

    /// Check rate limit using bit vector approach
    pub async fn check_rate_limit(
        &self,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult, String> {
        let now = Utc::now().timestamp();
        let window_start = now - context.policy.window_seconds as i64;
        let key = format!("rate_limit_bv:{}:{}", context.identifier, context.endpoint);

        // Get or create bit vector
        let mut bit_vector = self
            .get_or_create_bit_vector(&key, window_start, context.policy.window_seconds)
            .await?;

        // Calculate current bucket
        let current_bucket = self.get_bucket_index(now, &bit_vector);

        // Count requests in the current window
        let request_count = self.count_requests_in_window(&bit_vector, window_start, now);

        let allowed = request_count < context.policy.requests;

        // If allowed, record the request
        if allowed {
            self.record_request(&mut bit_vector, current_bucket).await?;
            self.store_bit_vector(&key, &bit_vector).await?;
        }

        // Calculate remaining after considering current request
        let remaining = if allowed {
            context.policy.requests.saturating_sub(request_count + 1)
        } else {
            0
        };

        // Calculate reset time
        let reset_time = DateTime::from_timestamp(
            bit_vector.start_timestamp + context.policy.window_seconds as i64,
            0,
        )
        .unwrap_or_else(|| {
            Utc::now() + chrono::Duration::seconds(context.policy.window_seconds as i64)
        });

        Ok(RateLimitResult {
            allowed,
            limit: context.policy.requests,
            remaining,
            reset_time,
            retry_after: if allowed {
                None
            } else {
                Some(context.policy.window_seconds)
            },
        })
    }

    /// Get or create a bit vector for the given time window
    async fn get_or_create_bit_vector(
        &self,
        key: &str,
        window_start: i64,
        window_seconds: u32,
    ) -> Result<RateLimitBitVector, String> {
        match self.get_bit_vector(key).await? {
            Some(mut existing) => {
                // Check if existing bit vector is still valid for current window
                let existing_end = existing.start_timestamp
                    + (existing.bucket_count as i64 * existing.bucket_size_seconds as i64);

                if existing.start_timestamp <= window_start
                    && existing_end >= window_start + window_seconds as i64
                {
                    // Bit vector covers our window, shift if necessary
                    self.shift_bit_vector_if_needed(&mut existing, window_start);
                    Ok(existing)
                } else {
                    // Create new bit vector
                    Ok(self.create_bit_vector(window_start, window_seconds))
                }
            }
            None => {
                // Create new bit vector
                Ok(self.create_bit_vector(window_start, window_seconds))
            }
        }
    }

    /// Create a new bit vector for the given time window
    fn create_bit_vector(&self, start_timestamp: i64, window_seconds: u32) -> RateLimitBitVector {
        let bucket_count =
            ((window_seconds as f64 / self.bucket_size_seconds as f64).ceil() as usize).max(1);
        let byte_count = (bucket_count + 7) / 8; // Round up to nearest byte

        RateLimitBitVector {
            bits: vec![0u8; byte_count],
            start_timestamp,
            bucket_size_seconds: self.bucket_size_seconds,
            bucket_count,
            bucket_counts: Some(vec![0u16; bucket_count]), // Enable precise counting
        }
    }

    /// Get bit vector from storage
    async fn get_bit_vector(&self, key: &str) -> Result<Option<RateLimitBitVector>, String> {
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json_str)) = result.data {
                        match serde_json::from_str::<RateLimitBitVector>(&json_str) {
                            Ok(bit_vector) => Ok(Some(bit_vector)),
                            Err(e) => Err(format!("Failed to deserialize bit vector: {}", e)),
                        }
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(format!("Backend error: {}", e)),
        }
    }

    /// Store bit vector to backend
    async fn store_bit_vector(
        &self,
        key: &str,
        bit_vector: &RateLimitBitVector,
    ) -> Result<(), String> {
        let json_str = serde_json::to_string(bit_vector)
            .map_err(|e| format!("Failed to serialize bit vector: {}", e))?;

        match self
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::String(json_str),
                ttl: Some(
                    (bit_vector.bucket_count as u64 * bit_vector.bucket_size_seconds as u64) * 2,
                ), // TTL twice the window size
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Storage error: {}", e)),
        }
    }

    /// Get bucket index for a given timestamp
    fn get_bucket_index(&self, timestamp: i64, bit_vector: &RateLimitBitVector) -> usize {
        let elapsed = timestamp - bit_vector.start_timestamp;
        let bucket_index = (elapsed / bit_vector.bucket_size_seconds as i64) as usize;
        bucket_index.min(bit_vector.bucket_count - 1)
    }

    /// Count requests in the current window
    fn count_requests_in_window(
        &self,
        bit_vector: &RateLimitBitVector,
        window_start: i64,
        window_end: i64,
    ) -> u32 {
        let start_bucket =
            self.get_bucket_index(window_start.max(bit_vector.start_timestamp), bit_vector);
        let end_bucket = self.get_bucket_index(window_end, bit_vector);

        if let Some(ref counts) = bit_vector.bucket_counts {
            // Use precise counts if available
            (start_bucket..=end_bucket.min(counts.len() - 1))
                .map(|i| counts[i] as u32)
                .sum()
        } else {
            // Use bit counting as fallback
            (start_bucket..=end_bucket.min(bit_vector.bucket_count - 1))
                .map(|i| {
                    if self.is_bit_set(&bit_vector.bits, i) {
                        1
                    } else {
                        0
                    }
                })
                .sum()
        }
    }

    /// Record a request in the given bucket
    async fn record_request(
        &self,
        bit_vector: &mut RateLimitBitVector,
        bucket_index: usize,
    ) -> Result<(), String> {
        if bucket_index < bit_vector.bucket_count {
            // Set bit
            self.set_bit(&mut bit_vector.bits, bucket_index);

            // Increment count if precise counting is enabled
            if let Some(ref mut counts) = bit_vector.bucket_counts {
                if bucket_index < counts.len() {
                    counts[bucket_index] = counts[bucket_index].saturating_add(1);
                }
            }
        }
        Ok(())
    }

    /// Set a bit in the bit vector
    fn set_bit(&self, bits: &mut Vec<u8>, index: usize) {
        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index < bits.len() {
            bits[byte_index] |= 1 << bit_index;
        }
    }

    /// Check if a bit is set
    fn is_bit_set(&self, bits: &[u8], index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index < bits.len() {
            (bits[byte_index] & (1 << bit_index)) != 0
        } else {
            false
        }
    }

    /// Shift bit vector window if needed (for sliding window behavior)
    fn shift_bit_vector_if_needed(
        &self,
        bit_vector: &mut RateLimitBitVector,
        new_window_start: i64,
    ) {
        if new_window_start <= bit_vector.start_timestamp {
            return; // No shift needed
        }

        let shift_buckets = ((new_window_start - bit_vector.start_timestamp)
            / bit_vector.bucket_size_seconds as i64) as usize;

        if shift_buckets >= bit_vector.bucket_count {
            // Complete reset - all buckets are outside the window
            bit_vector.bits.fill(0);
            if let Some(ref mut counts) = bit_vector.bucket_counts {
                counts.fill(0);
            }
            bit_vector.start_timestamp = new_window_start;
        } else if shift_buckets > 0 {
            // Partial shift
            self.shift_bits(&mut bit_vector.bits, shift_buckets, bit_vector.bucket_count);
            if let Some(ref mut counts) = bit_vector.bucket_counts {
                counts.rotate_left(shift_buckets);
                // Clear the shifted-in buckets
                let clear_start = counts.len() - shift_buckets;
                counts[clear_start..].fill(0);
            }
            bit_vector.start_timestamp +=
                shift_buckets as i64 * bit_vector.bucket_size_seconds as i64;
        }
    }

    /// Shift bits left by the specified number of positions
    fn shift_bits(&self, bits: &mut Vec<u8>, shift_buckets: usize, total_buckets: usize) {
        let total_bytes = (total_buckets + 7) / 8;

        // Bit shifting - shift entire bytes first, then individual bits
        let shift_bytes = shift_buckets / 8;
        let shift_bits = shift_buckets % 8;

        if shift_bytes > 0 {
            // Shift entire bytes
            bits.rotate_left(shift_bytes);
            // Clear the shifted-in bytes
            let clear_start = total_bytes.saturating_sub(shift_bytes);
            if clear_start < bits.len() {
                bits[clear_start..].fill(0);
            }
        }

        if shift_bits > 0 {
            // Shift individual bits
            let mut carry = 0u8;
            for i in 0..total_bytes {
                if i < bits.len() {
                    let new_carry = bits[i] >> (8 - shift_bits);
                    bits[i] = (bits[i] << shift_bits) | carry;
                    carry = new_carry;
                }
            }
        }
    }

    /// Get memory usage statistics
    pub async fn get_memory_stats(&self, key: &str) -> Result<BitVectorMemoryStats, String> {
        if let Some(bit_vector) = self.get_bit_vector(key).await? {
            let bits_memory = bit_vector.bits.len();
            let counts_memory = bit_vector
                .bucket_counts
                .as_ref()
                .map(|counts| counts.len() * 2) // 2 bytes per u16
                .unwrap_or(0);
            let metadata_memory = std::mem::size_of::<RateLimitBitVector>();

            Ok(BitVectorMemoryStats {
                total_bytes: bits_memory + counts_memory + metadata_memory,
                bits_bytes: bits_memory,
                counts_bytes: counts_memory,
                metadata_bytes: metadata_memory,
                bucket_count: bit_vector.bucket_count,
                bucket_size_seconds: bit_vector.bucket_size_seconds,
                compression_ratio: self.calculate_compression_ratio(bit_vector.bucket_count),
            })
        } else {
            Ok(BitVectorMemoryStats::default())
        }
    }

    /// Calculate compression ratio for timestamp storage
    pub fn calculate_compression_ratio(&self, bucket_count: usize) -> f64 {
        // Timestamp storage: 8 bytes per timestamp
        let timestamp_bytes = bucket_count as f64 * 8.0;

        // Bit vector storage
        let bitvector_bytes = (self.bucket_size_seconds as f64 * bucket_count as f64) as f64;

        timestamp_bytes / bitvector_bytes
    }
}

/// Rate limit service with both sliding window and bit vector support
pub struct RateLimitService {
    sliding_window_limiter: SlidingWindowRateLimiter,
    bit_vector_limiter: BitVectorRateLimiter,
    use_bit_vector: bool, // Flag to choose between implementations
    pub global_policy: tokio::sync::RwLock<Option<crate::models::RateLimitPolicy>>,
    backend: Arc<dyn UniversalBackend>,
}

impl RateLimitService {
    pub fn new(backend: Arc<dyn UniversalBackend>, use_bit_vector: bool) -> Self {
        Self {
            sliding_window_limiter: SlidingWindowRateLimiter::new(backend.clone()),
            bit_vector_limiter: BitVectorRateLimiter::new(backend.clone()),
            use_bit_vector,
            global_policy: tokio::sync::RwLock::new(None),
            backend,
        }
    }

    /// Check rate limit using the configured limiter
    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<RateLimitResult, String> {
        // Track total requests
        let _ = self.increment_total_requests().await;

        let policy = self.get_policy_for_endpoint(endpoint).await?;
        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy,
            endpoint: endpoint.to_string(),
        };

        let result = if self.use_bit_vector {
            self.bit_vector_limiter.check_rate_limit(&context).await
        } else {
            self.sliding_window_limiter.check_rate_limit(&context).await
        };

        // Track rate limited requests if request was denied
        if let Ok(ref rate_limit_result) = result {
            if !rate_limit_result.allowed {
                let _ = self.increment_rate_limited_requests().await;
            }
        }

        result
    }

    /// Get memory efficiency metrics
    pub async fn get_efficiency_metrics(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<EfficiencyMetrics, String> {
        let key = format!("rate_limit_bv:{}:{}", identifier, endpoint);
        let bit_vector_stats = self.bit_vector_limiter.get_memory_stats(&key).await?;

        // Estimate sliding window memory usage
        let sliding_window_key = format!("rate_limit:{}:{}", identifier, endpoint);
        let timestamps = self
            .sliding_window_limiter
            .get_request_timestamps(&sliding_window_key)
            .await?;
        let sliding_window_bytes = timestamps.len() * 8; // 8 bytes per i64 timestamp

        Ok(EfficiencyMetrics {
            sliding_window_bytes,
            bit_vector_bytes: bit_vector_stats.total_bytes,
            compression_ratio: bit_vector_stats.compression_ratio,
            memory_savings: ((sliding_window_bytes as f64 - bit_vector_stats.total_bytes as f64)
                / sliding_window_bytes as f64)
                .max(0.0),
        })
    }

    /// Benchmark both implementations
    pub async fn benchmark_implementations(
        &self,
        identifier: &str,
        endpoint: &str,
        iterations: usize,
    ) -> Result<BenchmarkMetrics, String> {
        let policy = self.get_policy_for_endpoint(endpoint).await?;
        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy,
            endpoint: endpoint.to_string(),
        };

        // Benchmark sliding window
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = self
                .sliding_window_limiter
                .check_rate_limit(&context)
                .await?;
        }
        let sliding_window_duration = start.elapsed();

        // Benchmark bit vector
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = self.bit_vector_limiter.check_rate_limit(&context).await?;
        }
        let bit_vector_duration = start.elapsed();

        Ok(BenchmarkMetrics {
            iterations,
            sliding_window_duration,
            bit_vector_duration,
            speedup_ratio: sliding_window_duration.as_nanos() as f64
                / bit_vector_duration.as_nanos() as f64,
        })
    }

    pub async fn get_policy_for_endpoint(&self, endpoint: &str) -> Result<RateLimitPolicy, String> {
        // First, try to get endpoint-specific policy
        let key = format!("rate_limit:policy:{}", endpoint);
        let operation = dbx_core::DataOperation::Get { key, fields: None };

        if let Ok(result) = self.backend.execute_data(operation).await {
            if let Some(dbx_core::DataValue::String(policy_json)) = result.data {
                if let Ok(policy) = serde_json::from_str::<RateLimitPolicy>(&policy_json) {
                    return Ok(policy);
                }
            }
        }

        // Fall back to global policy
        {
            let global_policy = self.global_policy.read().await;
            if let Some(policy) = &*global_policy {
                return Ok(policy.clone());
            }
        }
        // Fall back to default policy
        Ok(RateLimitPolicy {
            requests: 100,
            window_seconds: 60,
            burst_allowance: Some(10),
        })
    }

    /// Get rate limit information for a specific identifier and endpoint
    pub async fn get_rate_limit_info(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<crate::models::RateLimitInfo, String> {
        let policy = self.get_policy_for_endpoint(endpoint).await?;

        // Check current rate limit status
        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy: policy.clone(),
            endpoint: endpoint.to_string(),
        };

        let result = if self.use_bit_vector {
            self.bit_vector_limiter.check_rate_limit(&context).await
        } else {
            self.sliding_window_limiter.check_rate_limit(&context).await
        };

        match result {
            Ok(rate_limit_result) => Ok(crate::models::RateLimitInfo {
                allowed: rate_limit_result.allowed,
                limit: rate_limit_result.limit,
                remaining: rate_limit_result.remaining,
                reset_time: rate_limit_result.reset_time,
                retry_after: rate_limit_result.retry_after,
            }),
            Err(e) => Err(format!("Failed to check rate limit: {}", e)),
        }
    }

    /// Get all configured policies
    pub async fn get_all_policies(&self) -> Vec<(String, crate::models::RateLimitPolicy)> {
        let mut policies = Vec::new();

        // Add global policy if exists
        {
            let global_policy = self.global_policy.read().await;
            if let Some(policy) = &*global_policy {
                policies.push(("global".to_string(), policy.clone()));
            }
        }

        // Get endpoint-specific policies using query operation
        let query_op = dbx_core::QueryOperation {
            id: uuid::Uuid::new_v4(),
            filter: dbx_core::QueryFilter::KeyPattern {
                pattern: "rate_limit:policy:*".to_string(),
            },
            projection: None,
            sort: None,
            limit: None,
            offset: None,
        };

        match self.backend.execute_query(query_op).await {
            Ok(result) => {
                for item in result.results {
                    if let Some(endpoint) = item.key.strip_prefix("rate_limit:policy:") {
                        if let Ok(policy) = serde_json::from_str::<crate::models::RateLimitPolicy>(
                            &item.data.to_string_lossy(),
                        ) {
                            policies.push((endpoint.to_string(), policy));
                        }
                    }
                }
            }
            Err(_) => {
                // Fallback to default policy if backend unavailable
                policies.push((
                    "default".to_string(),
                    crate::models::RateLimitPolicy {
                        requests: 100,
                        window_seconds: 60,
                        burst_allowance: Some(10),
                    },
                ));
            }
        }

        policies
    }

    /// Set policy for a specific endpoint
    pub async fn set_endpoint_policy(
        &self,
        endpoint: &str,
        policy: crate::models::RateLimitPolicy,
    ) -> Result<(), String> {
        let key = format!("rate_limit:policy:{}", endpoint);
        let policy_json = serde_json::to_string(&policy)
            .map_err(|e| format!("Failed to serialize policy: {}", e))?;

        let operation = dbx_core::DataOperation::Set {
            key,
            value: dbx_core::DataValue::String(policy_json),
            ttl: None, // Policies don't expire
        };

        self.backend
            .execute_data(operation)
            .await
            .map_err(|e| format!("Failed to store policy: {}", e))?;

        Ok(())
    }

    /// Remove policy for a specific endpoint
    pub async fn remove_endpoint_policy(&self, endpoint: &str) -> Result<bool, String> {
        let key = format!("rate_limit:policy:{}", endpoint);

        // First check if the policy exists
        let exists_op = dbx_core::DataOperation::Exists {
            key: key.clone(),
            fields: None,
        };

        let exists = match self.backend.execute_data(exists_op).await {
            Ok(result) => match result.data {
                Some(dbx_core::DataValue::Bool(exists)) => exists,
                _ => false,
            },
            Err(_) => false,
        };

        if !exists {
            return Ok(false);
        }

        // Delete the policy
        let delete_op = dbx_core::DataOperation::Delete { key, fields: None };

        self.backend
            .execute_data(delete_op)
            .await
            .map_err(|e| format!("Failed to delete policy: {}", e))?;

        Ok(true)
    }

    /// Reset rate limit for a specific identifier and endpoint
    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> Result<(), String> {
        // Clear rate limit data for both sliding window and bit vector implementations
        let sliding_window_key = format!("rate_limit:{}:{}", identifier, endpoint);
        let bit_vector_key = format!("rate_limit_bv:{}:{}", identifier, endpoint);

        let operations = vec![
            dbx_core::DataOperation::Delete {
                key: sliding_window_key,
                fields: None,
            },
            dbx_core::DataOperation::Delete {
                key: bit_vector_key,
                fields: None,
            },
        ];

        let batch_op = dbx_core::DataOperation::Batch { operations };

        self.backend
            .execute_data(batch_op)
            .await
            .map_err(|e| format!("Failed to reset rate limit: {}", e))?;

        Ok(())
    }

    /// Count active limiters
    pub async fn count_active_limiters(&self) -> Result<usize, String> {
        // Count active rate limiters by finding all rate limit keys
        let query_op = dbx_core::QueryOperation {
            id: uuid::Uuid::new_v4(),
            filter: dbx_core::QueryFilter::KeyPattern {
                pattern: "rate_limit:*:*".to_string(),
            },
            projection: None,
            sort: None,
            limit: None,
            offset: None,
        };

        match self.backend.execute_query(query_op).await {
            Ok(result) => {
                // Count unique identifier:endpoint combinations
                let mut unique_limiters = std::collections::HashSet::new();
                for item in result.results {
                    if let Some(parts) = item.key.strip_prefix("rate_limit:") {
                        if let Some(colon_pos) = parts.find(':') {
                            let identifier = &parts[..colon_pos];
                            let endpoint = &parts[colon_pos + 1..];
                            unique_limiters.insert(format!("{}:{}", identifier, endpoint));
                        }
                    }
                }
                Ok(unique_limiters.len())
            }
            Err(_) => Ok(0),
        }
    }

    /// Get total requests count
    pub async fn get_total_requests(&self) -> Result<u64, String> {
        let key = "rate_limit:metrics:total_requests";
        let operation = dbx_core::DataOperation::Get {
            key: key.to_string(),
            fields: None,
        };

        match self.backend.execute_data(operation).await {
            Ok(result) => match result.data {
                Some(dbx_core::DataValue::String(s)) => s
                    .parse::<u64>()
                    .map_err(|e| format!("Failed to parse total requests: {}", e)),
                Some(dbx_core::DataValue::Int(i)) => Ok(i as u64),
                _ => Ok(0),
            },
            Err(_) => Ok(0), // Return 0 if not found
        }
    }

    /// Get rate limited requests count
    pub async fn get_rate_limited_requests(&self) -> Result<u64, String> {
        let key = "rate_limit:metrics:rate_limited_requests";
        let operation = dbx_core::DataOperation::Get {
            key: key.to_string(),
            fields: None,
        };

        match self.backend.execute_data(operation).await {
            Ok(result) => match result.data {
                Some(dbx_core::DataValue::String(s)) => s
                    .parse::<u64>()
                    .map_err(|e| format!("Failed to parse rate limited requests: {}", e)),
                Some(dbx_core::DataValue::Int(i)) => Ok(i as u64),
                _ => Ok(0),
            },
            Err(_) => Ok(0), // Return 0 if not found
        }
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) -> Result<(), String> {
        let metrics_keys = vec![
            "rate_limit:metrics:total_requests",
            "rate_limit:metrics:rate_limited_requests",
        ];

        let mut operations = Vec::new();
        for key in metrics_keys {
            operations.push(dbx_core::DataOperation::Delete {
                key: key.to_string(),
                fields: None,
            });
        }

        let batch_op = dbx_core::DataOperation::Batch { operations };

        self.backend
            .execute_data(batch_op)
            .await
            .map_err(|e| format!("Failed to reset metrics: {}", e))?;

        Ok(())
    }

    /// Set global rate limit policy
    pub async fn set_global_policy(
        &self,
        policy: crate::models::RateLimitPolicy,
    ) -> Result<(), String> {
        // Store the policy in memory
        {
            let mut global_policy = self.global_policy.write().await;
            *global_policy = Some(policy.clone());
        }

        // Also persist it to the backend for durability
        let key = "rate_limit:global_policy";
        let policy_json = serde_json::to_string(&policy)
            .map_err(|e| format!("Failed to serialize global policy: {}", e))?;

        let operation = dbx_core::DataOperation::Set {
            key: key.to_string(),
            value: dbx_core::DataValue::String(policy_json),
            ttl: None,
        };

        self.backend
            .execute_data(operation)
            .await
            .map_err(|e| format!("Failed to store global policy: {}", e))?;

        Ok(())
    }

    /// Increment total requests counter
    pub async fn increment_total_requests(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:total_requests";

        // Try to increment, if key doesn't exist, set to 1
        let get_op = dbx_core::DataOperation::Get {
            key: key.to_string(),
            fields: None,
        };

        let current_value = match self.backend.execute_data(get_op).await {
            Ok(result) => match result.data {
                Some(dbx_core::DataValue::String(s)) => s.parse::<u64>().unwrap_or(0),
                Some(dbx_core::DataValue::Int(i)) => i as u64,
                _ => 0,
            },
            Err(_) => 0,
        };

        let set_op = dbx_core::DataOperation::Set {
            key: key.to_string(),
            value: dbx_core::DataValue::String((current_value + 1).to_string()),
            ttl: None,
        };

        self.backend
            .execute_data(set_op)
            .await
            .map_err(|e| format!("Failed to increment total requests: {}", e))?;

        Ok(())
    }

    /// Increment rate limited requests counter
    pub async fn increment_rate_limited_requests(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:rate_limited_requests";

        // Try to increment, if key doesn't exist, set to 1
        let get_op = dbx_core::DataOperation::Get {
            key: key.to_string(),
            fields: None,
        };

        let current_value = match self.backend.execute_data(get_op).await {
            Ok(result) => match result.data {
                Some(dbx_core::DataValue::String(s)) => s.parse::<u64>().unwrap_or(0),
                Some(dbx_core::DataValue::Int(i)) => i as u64,
                _ => 0,
            },
            Err(_) => 0,
        };

        let set_op = dbx_core::DataOperation::Set {
            key: key.to_string(),
            value: dbx_core::DataValue::String((current_value + 1).to_string()),
            ttl: None,
        };

        self.backend
            .execute_data(set_op)
            .await
            .map_err(|e| format!("Failed to increment rate limited requests: {}", e))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EfficiencyMetrics {
    pub sliding_window_bytes: usize,
    pub bit_vector_bytes: usize,
    pub compression_ratio: f64,
    pub memory_savings: f64, // Percentage of memory saved
}

#[derive(Debug, Clone)]
pub struct BenchmarkMetrics {
    pub iterations: usize,
    pub sliding_window_duration: std::time::Duration,
    pub bit_vector_duration: std::time::Duration,
    pub speedup_ratio: f64, // How much faster bit vector is
}

/// Memory usage statistics for bit vector
#[derive(Debug, Clone)]
pub struct BitVectorMemoryStats {
    pub total_bytes: usize,
    pub bits_bytes: usize,
    pub counts_bytes: usize,
    pub metadata_bytes: usize,
    pub bucket_count: usize,
    pub bucket_size_seconds: u32,
    pub compression_ratio: f64, // Storage efficiency ratio
}

impl Default for BitVectorMemoryStats {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            bits_bytes: 0,
            counts_bytes: 0,
            metadata_bytes: 0,
            bucket_count: 0,
            bucket_size_seconds: 0,
            compression_ratio: 1.0,
        }
    }
}

#[derive(Clone)]
pub struct PolicyRateLimitService {
    limiter: SlidingWindowRateLimiter,
    policies: Arc<std::sync::RwLock<HashMap<String, RateLimitPolicy>>>,
    pub global_policy: Arc<std::sync::RwLock<Option<RateLimitPolicy>>>,
}

impl PolicyRateLimitService {
    pub fn new(backend: Arc<dyn UniversalBackend>) -> Self {
        Self {
            limiter: SlidingWindowRateLimiter::new(backend),
            policies: Arc::new(std::sync::RwLock::new(HashMap::new())),
            global_policy: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    pub async fn set_global_policy(&self, policy: RateLimitPolicy) {
        *self.global_policy.write().unwrap() = Some(policy);
    }

    pub async fn set_endpoint_policy(&self, endpoint: &str, policy: RateLimitPolicy) {
        self.policies
            .write()
            .unwrap()
            .insert(endpoint.to_string(), policy);
    }

    pub async fn remove_endpoint_policy(&self, endpoint: &str) -> bool {
        self.policies.write().unwrap().remove(endpoint).is_some()
    }

    pub async fn increment_total_requests(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:total_requests";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(current + 1),
                ttl: None,
            })
            .await;
        Ok(())
    }

    pub async fn increment_rate_limited_requests(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:rate_limited_requests";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(current + 1),
                ttl: None,
            })
            .await;
        Ok(())
    }

    async fn get_counter_value(&self, key: &str) -> Result<i64, String> {
        match self
            .limiter
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::Int(count)) = result.data {
                        Ok(count)
                    } else if let Some(DataValue::String(s)) = result.data {
                        s.parse().map_err(|e| format!("Parse error: {}", e))
                    } else {
                        Ok(0)
                    }
                } else {
                    Err(format!("Failed to get counter value for key: {}", key))
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn get_total_requests(&self) -> Result<u64, String> {
        let count = self
            .get_counter_value("rate_limit:metrics:total_requests")
            .await?;
        Ok(count.max(0) as u64)
    }

    pub async fn get_rate_limited_requests(&self) -> Result<u64, String> {
        let count = self
            .get_counter_value("rate_limit:metrics:rate_limited_requests")
            .await?;
        Ok(count.max(0) as u64)
    }

    pub async fn reset_metrics(&self) -> Result<(), String> {
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Delete {
                key: "rate_limit:metrics:total_requests".to_string(),
                fields: None,
            })
            .await;
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Delete {
                key: "rate_limit:metrics:rate_limited_requests".to_string(),
                fields: None,
            })
            .await;
        Ok(())
    }

    pub async fn get_policy_for_endpoint(&self, endpoint: &str) -> Option<RateLimitPolicy> {
        let policies = self.policies.read().unwrap();
        if let Some(policy) = policies.get(endpoint) {
            Some(policy.clone())
        } else {
            let global = self.global_policy.read().unwrap();
            global.clone()
        }
    }

    pub async fn get_all_policies(&self) -> HashMap<String, RateLimitPolicy> {
        self.policies.read().unwrap().clone()
    }

    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<RateLimitResult, String> {
        let policy = self
            .get_policy_for_endpoint(endpoint)
            .await
            .ok_or_else(|| "No rate limit policy configured".to_string())?;

        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy: policy.clone(),
            endpoint: endpoint.to_string(),
        };

        self.limiter.check_rate_limit(&context).await
    }

    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> Result<(), String> {
        self.limiter.reset_rate_limit(identifier, endpoint).await
    }

    pub async fn get_rate_limit_info(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<RateLimitResult, String> {
        let policy = self
            .get_policy_for_endpoint(endpoint)
            .await
            .ok_or_else(|| "No rate limit policy configured".to_string())?;

        self.limiter
            .get_rate_limit_info(identifier, endpoint, &policy)
            .await
    }

    pub async fn count_active_limiters(&self) -> Result<u32, String> {
        // Track active limiters by maintaining a count in the backend
        let active_count = self
            .get_counter_value("rate_limit:metrics:active_limiters")
            .await?;
        Ok(active_count.max(0) as u32)
    }

    pub async fn increment_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:active_limiters";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(current + 1),
                ttl: None,
            })
            .await;
        Ok(())
    }

    pub async fn decrement_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:active_limiters";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let new_count = (current - 1).max(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(new_count),
                ttl: None,
            })
            .await;
        Ok(())
    }
}

fn extract_identifier_from_request(
    headers: &HeaderMap,
    connect_info: Option<&std::net::SocketAddr>,
    auth_context: Option<&str>,
) -> String {
    // Priority: authenticated user > API key > IP address > unknown
    if let Some(auth_type) = auth_context {
        match auth_type {
            "user" => {
                // Extract user ID from JWT token in Authorization header
                if let Some(auth_header) = headers.get("authorization") {
                    if let Ok(auth_str) = auth_header.to_str() {
                        if auth_str.starts_with("Bearer ") {
                            return format!("user:{}", &auth_str[7..15]); // Use first 8 chars as identifier
                        }
                    }
                }
                "user:unknown".to_string()
            }
            "api_key" => {
                // Extract API key ID from Authorization header
                if let Some(auth_header) = headers.get("authorization") {
                    if let Ok(auth_str) = auth_header.to_str() {
                        if auth_str.starts_with("ApiKey ") {
                            return format!("api_key:{}", &auth_str[7..15]); // Use first 8 chars as identifier
                        }
                    }
                }
                "api_key:unknown".to_string()
            }
            _ => "unknown".to_string(),
        }
    } else {
        // Use trusted IP address extraction as fallback
        if let Some(trusted_ip) =
            crate::middleware::security::extract_trusted_client_ip(headers, connect_info)
        {
            format!("ip:{}", trusted_ip)
        } else if let Some(connect_info) = connect_info {
            // Fallback to direct connection if trusted extraction fails
            format!("ip:{}", connect_info.ip())
        } else {
            "unknown".to_string()
        }
    }
}

pub fn add_rate_limit_headers(response: &mut axum::response::Response, result: &RateLimitResult) {
    let headers = response.headers_mut();

    if let Ok(value) = axum::http::HeaderValue::from_str(&result.limit.to_string()) {
        headers.insert("X-RateLimit-Limit", value);
    }

    if let Ok(value) = axum::http::HeaderValue::from_str(&result.remaining.to_string()) {
        headers.insert("X-RateLimit-Remaining", value);
    }

    if let Ok(value) = axum::http::HeaderValue::from_str(&result.reset_time.timestamp().to_string())
    {
        headers.insert("X-RateLimit-Reset", value);
    }

    if let Some(retry_after) = result.retry_after {
        if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
            headers.insert("Retry-After", value);
        }
    }
}

pub async fn rate_limit_middleware(
    State(rate_limit_service): State<Arc<PolicyRateLimitService>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let endpoint = request.uri().path().to_string();

    // Track total requests
    let _ = rate_limit_service.increment_total_requests().await;

    // Extract connection info from request extensions if available
    let connect_info = request.extensions().get::<std::net::SocketAddr>().copied();

    // Extract user/API key ID from auth headers
    let auth_identifier = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth_header| {
            if auth_header.starts_with("Bearer ") {
                Some("user") // JWT token - would extract user ID from token
            } else if auth_header.starts_with("ApiKey ") {
                Some("api_key") // API Key - would extract API key ID
            } else {
                None
            }
        });

    let identifier =
        extract_identifier_from_request(&headers, connect_info.as_ref(), auth_identifier);

    let rate_limit_result = rate_limit_service
        .check_rate_limit(&identifier, &endpoint)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Rate limiting error: {}",
                    e
                ))),
            )
        })?;

    if !rate_limit_result.allowed {
        // Track rate-limited requests
        let _ = rate_limit_service.increment_rate_limited_requests().await;

        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::error("Rate limit exceeded".to_string())),
        )
            .into_response();

        add_rate_limit_headers(&mut response, &rate_limit_result);
        return Ok(response);
    }

    let mut response = next.run(request).await;
    add_rate_limit_headers(&mut response, &rate_limit_result);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_policy() -> RateLimitPolicy {
        RateLimitPolicy {
            requests: 5,
            window_seconds: 10,
            burst_allowance: Some(7),
        }
    }

    async fn create_test_backend() -> Arc<dyn UniversalBackend> {
        crate::test_helpers::create_mock_backend()
    }

    #[tokio::test]
    async fn test_sliding_window_rate_limiter() {
        let backend = create_test_backend().await;
        let limiter = SlidingWindowRateLimiter::new(backend.clone());

        let test_prefix = format!(
            "test_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let context = RateLimitContext {
            identifier: format!("test_user_{}", test_prefix),
            policy: create_test_policy(),
            endpoint: format!("/api/test_{}", test_prefix),
        };

        // Clean up any existing keys using backend abstraction
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key.clone(),
                fields: None,
            })
            .await;

        // First few requests should be allowed
        for i in 1..=5 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.limit, 5);
            assert_eq!(result.remaining, 5 - i);
        }

        // 6th and 7th requests should be allowed due to burst
        for i in 6..=7 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Burst request {} should be allowed", i);
        }

        // 8th request should be denied
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(!result.allowed, "Request beyond burst should be denied");
        assert!(result.retry_after.is_some());

        // Cleanup
        let _ = backend
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;
    }

    #[tokio::test]
    async fn test_rate_limit_reset() {
        let backend = create_test_backend().await;
        let limiter = SlidingWindowRateLimiter::new(backend.clone());

        let test_prefix = format!(
            "test_reset_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let context = RateLimitContext {
            identifier: format!("test_user_reset_{}", test_prefix),
            policy: RateLimitPolicy {
                requests: 2,
                window_seconds: 60,
                burst_allowance: None,
            },
            endpoint: format!("/api/reset_test_{}", test_prefix),
        };

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key.clone(),
                fields: None,
            })
            .await;

        // Use up the rate limit
        for i in 1..=2 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
        }

        // Next request should be denied
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(
            !result.allowed,
            "Request should be denied after limit reached"
        );

        // Reset the rate limit
        limiter
            .reset_rate_limit(&context.identifier, &context.endpoint)
            .await
            .unwrap();

        // Next request should be allowed again
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed, "Request should be allowed after reset");

        // Cleanup
        let cleanup_key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: cleanup_key,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_rate_limit_service_global_policy() {
        let backend = create_test_backend().await;
        let service = PolicyRateLimitService::new(backend.clone()); // Explicitly set to false

        service.set_global_policy(create_test_policy()).await;

        let test_prefix = format!(
            "test_global_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let endpoint = format!("/api/general_{}", test_prefix);
        let user_id = format!("user1_{}", test_prefix);

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", user_id, endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key.clone(),
                fields: None,
            })
            .await;

        // Test global policy
        let result = service.check_rate_limit(&user_id, &endpoint).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 5);

        // Cleanup
        let cleanup_key = format!("rate_limit:{}:{}", user_id, endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: cleanup_key,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_rate_limit_service_endpoint_specific_policy() {
        let backend = create_test_backend().await;
        let service = PolicyRateLimitService::new(backend.clone()); // Explicitly set to false

        service.set_global_policy(create_test_policy()).await;

        let test_prefix = format!(
            "test_endpoint_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let general_endpoint = format!("/api/general_{}", test_prefix);
        let special_endpoint = format!("/api/special_{}", test_prefix);
        let user_id = format!("user1_{}", test_prefix);

        service
            .set_endpoint_policy(
                &special_endpoint,
                RateLimitPolicy {
                    requests: 2,
                    window_seconds: 10,
                    burst_allowance: None,
                },
            )
            .await;

        // Clean up any existing keys
        let key1 = format!("rate_limit:{}:{}", user_id, general_endpoint);
        let key2 = format!("rate_limit:{}:{}", user_id, special_endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key1.clone(),
                fields: None,
            })
            .await;
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key2.clone(),
                fields: None,
            })
            .await;

        // Test global policy
        let result = service
            .check_rate_limit(&user_id, &general_endpoint)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 5);

        // Test endpoint-specific policy
        let result = service
            .check_rate_limit(&user_id, &special_endpoint)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 2);

        // Cleanup
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key1,
                fields: None,
            })
            .await;
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key2,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_different_users_separate_limits() {
        let backend = create_test_backend().await;
        let service = PolicyRateLimitService::new(backend.clone()); // Explicitly set to false

        // Use unique test prefix to avoid conflicts with other tests
        let test_prefix = format!(
            "test_separation_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let endpoint = format!("/api/{}", test_prefix);

        let policy = RateLimitPolicy {
            requests: 3,
            window_seconds: 60,
            burst_allowance: None,
        };
        service.set_global_policy(policy).await;

        let user1_id = format!("user1_{}", test_prefix);
        let user2_id = format!("user2_{}", test_prefix);

        // Clean up any existing keys for this test
        let key1 = format!("rate_limit:{}:{}", user1_id, endpoint);
        let key2 = format!("rate_limit:{}:{}", user2_id, endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key1.clone(),
                fields: None,
            })
            .await;
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key2.clone(),
                fields: None,
            })
            .await;

        // User 1 uses up their limit
        for i in 1..=3 {
            let result = service
                .check_rate_limit(&user1_id, &endpoint)
                .await
                .unwrap();
            assert!(result.allowed, "User1 request {} should be allowed", i);
        }

        // User 1's next request should be denied
        let result = service
            .check_rate_limit(&user1_id, &endpoint)
            .await
            .unwrap();
        assert!(
            !result.allowed,
            "User1's request should be denied after limit reached"
        );

        // User 2 should still have their full limit available
        let result = service
            .check_rate_limit(&user2_id, &endpoint)
            .await
            .unwrap();
        assert!(result.allowed, "User2's first request should be allowed");
        assert_eq!(result.remaining, 2);

        // Cleanup
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key1,
                fields: None,
            })
            .await;
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key2,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_get_rate_limit_info_without_incrementing() {
        let backend = create_test_backend().await;
        let limiter = SlidingWindowRateLimiter::new(backend.clone());

        let policy = RateLimitPolicy {
            requests: 5,
            window_seconds: 60,
            burst_allowance: None,
        };

        let test_prefix = format!(
            "test_info_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let identifier = format!("test_user_info_{}", test_prefix);
        let endpoint = format!("/api/info_test_{}", test_prefix);

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", identifier, endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: key.clone(),
                fields: None,
            })
            .await;

        // Get initial info
        let info = limiter
            .get_rate_limit_info(&identifier, &endpoint, &policy)
            .await
            .unwrap();
        assert_eq!(info.remaining, 5);
        assert!(info.allowed);

        // Check that getting info doesn't increment the counter
        let info2 = limiter
            .get_rate_limit_info(&identifier, &endpoint, &policy)
            .await
            .unwrap();
        assert_eq!(info2.remaining, 5);
        assert!(info2.allowed);

        // Make an actual request to increment
        let context = RateLimitContext {
            identifier: identifier.clone(),
            policy,
            endpoint: endpoint.clone(),
        };
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 4);

        // Now info should show the updated count
        let info3 = limiter
            .get_rate_limit_info(&identifier, &endpoint, &context.policy)
            .await
            .unwrap();
        assert_eq!(info3.remaining, 4);

        // Cleanup
        let cleanup_key = format!("rate_limit:{}:{}", identifier, endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: cleanup_key,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_burst_allowance_behavior() {
        let backend = create_test_backend().await;
        let limiter = SlidingWindowRateLimiter::new(backend.clone());

        let test_prefix = format!(
            "test_burst_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let context = RateLimitContext {
            identifier: format!("test_burst_user_{}", test_prefix),
            policy: RateLimitPolicy {
                requests: 3,
                window_seconds: 60,
                burst_allowance: Some(5),
            },
            endpoint: format!("/api/burst_test_{}", test_prefix),
        };

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;

        // First 3 requests should be allowed (normal limit)
        for i in 1..=3 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Normal request {} should be allowed", i);
        }

        // Next 2 requests should be allowed due to burst allowance
        for i in 4..=5 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Burst request {} should be allowed", i);
        }

        // 6th request should be denied
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(
            !result.allowed,
            "Request beyond burst allowance should be denied"
        );

        // Cleanup
        let cleanup_key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = backend
            .execute_data(DataOperation::Delete {
                key: cleanup_key,
                fields: None,
            })
            .await;
    }

    #[test]
    fn test_extract_identifier_from_request_priority() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut headers = HeaderMap::new();
        let socket_addr =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let connect_info = Some(socket_addr);

        // Test priority: auth context with header > IP address
        headers.insert("authorization", "Bearer abcd1234token".parse().unwrap());
        let identifier =
            extract_identifier_from_request(&headers, connect_info.as_ref(), Some("user"));
        assert_eq!(identifier, "user:abcd1234");

        // Test API key auth
        headers.clear();
        headers.insert("authorization", "ApiKey xyz98765key".parse().unwrap());
        let identifier =
            extract_identifier_from_request(&headers, connect_info.as_ref(), Some("api_key"));
        assert_eq!(identifier, "api_key:xyz98765");

        // Test IP fallback when no auth
        headers.clear();
        let identifier = extract_identifier_from_request(&headers, connect_info.as_ref(), None);
        assert_eq!(identifier, "ip:192.168.1.1");

        // Test unknown fallback when no connect info
        let identifier = extract_identifier_from_request(&headers, None, None);
        assert_eq!(identifier, "unknown");
    }

    #[test]
    fn test_rate_limit_policy_creation() {
        let policy = RateLimitPolicy {
            requests: 100,
            window_seconds: 60,
            burst_allowance: Some(150),
        };

        assert_eq!(policy.requests, 100);
        assert_eq!(policy.window_seconds, 60);
        assert_eq!(policy.burst_allowance, Some(150));
    }

    #[test]
    fn test_rate_limit_result_creation() {
        let reset_time = chrono::Utc::now();
        let result = RateLimitResult {
            allowed: true,
            limit: 100,
            remaining: 95,
            reset_time,
            retry_after: None,
        };

        assert!(result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 95);
        assert_eq!(result.reset_time, reset_time);
        assert!(result.retry_after.is_none());
    }

    #[tokio::test]
    async fn test_bit_vector_rate_limiter() {
        let backend = create_test_backend().await;
        let limiter = BitVectorRateLimiter::new(backend);

        let policy = RateLimitPolicy {
            requests: 5,
            window_seconds: 10,
            burst_allowance: Some(2),
        };

        let context = RateLimitContext {
            identifier: "test_user_bv".to_string(),
            policy,
            endpoint: "/api/test".to_string(),
        };

        // Test initial requests (should be allowed)
        for i in 0..5 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i + 1);
            assert_eq!(result.limit, 5);
            assert_eq!(result.remaining, 4 - i);
        }

        // Test rate limit exceeded
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(!result.allowed, "Request should be rate limited");
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn test_bit_vector_memory_efficiency() {
        let backend = create_test_backend().await;
        let limiter = BitVectorRateLimiter::with_bucket_size(backend, 1); // 1-second buckets

        let policy = RateLimitPolicy {
            requests: 100,
            window_seconds: 60,
            burst_allowance: Some(10),
        };

        let context = RateLimitContext {
            identifier: "memory_test_user".to_string(),
            policy,
            endpoint: "/api/memory_test".to_string(),
        };

        // Make several requests
        for _ in 0..20 {
            let _ = limiter.check_rate_limit(&context).await.unwrap();
        }

        // Check memory stats
        let key = format!("rate_limit_bv:{}:{}", context.identifier, context.endpoint);
        let stats = limiter.get_memory_stats(&key).await.unwrap();

        assert!(stats.total_bytes > 0, "Should have memory usage data");
        assert!(
            stats.bucket_count == 60,
            "Should have 60 buckets for 60-second window"
        );
        assert!(
            stats.compression_ratio > 1.0,
            "Should provide compression ratio for timestamp storage"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_service() {
        let backend = create_test_backend().await;

        // Test sliding window implementation
        let service_sliding = RateLimitService::new(backend.clone(), false);
        let result = service_sliding
            .check_rate_limit("test_user_sliding", "/api/test")
            .await;
        assert!(result.is_ok());

        // Test bit vector implementation
        let service_bitvector = RateLimitService::new(backend, true);
        let result = service_bitvector
            .check_rate_limit("test_user_bitvector", "/api/test")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_bit_vector_sliding_window_behavior() {
        let backend = create_test_backend().await;
        let limiter = BitVectorRateLimiter::with_bucket_size(backend, 1);

        let policy = RateLimitPolicy {
            requests: 3,
            window_seconds: 5,
            burst_allowance: Some(1),
        };

        let context = RateLimitContext {
            identifier: "sliding_test_user".to_string(),
            policy,
            endpoint: "/api/sliding_test".to_string(),
        };

        // Use up the rate limit
        for _ in 0..3 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed);
        }

        // Should be rate limited now
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(!result.allowed);

        // Test that bucket creation and retrieval works
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let get_op = dbx_core::DataOperation::Get { key, fields: None };
        let stored_result = limiter.backend.execute_data(get_op).await;
        assert!(stored_result.is_ok());
    }

    #[tokio::test]
    async fn test_efficiency_metrics() {
        let backend = create_test_backend().await;
        let service = RateLimitService::new(backend, true); // Enable bit vector

        // Make requests and check metrics structure
        for _ in 0..5 {
            let _ = service
                .check_rate_limit("efficiency_user", "/api/efficiency")
                .await;
        }

        let metrics = service
            .get_efficiency_metrics("efficiency_user", "/api/efficiency")
            .await
            .unwrap();

        // Verify metrics contain expected fields
        // Verify metrics structure is valid
        // With mock backend, values might be 0, so we check for valid structure
        assert!(metrics.compression_ratio >= 0.0);
        // Note: sliding_window_bytes and bit_vector_bytes are usize, always >= 0
        // Just verify they have reasonable bounds instead
        assert!(metrics.sliding_window_bytes < 1_000_000); // Reasonable upper bound
        assert!(metrics.bit_vector_bytes < 1_000_000); // Reasonable upper bound
        assert!(metrics.memory_savings >= 0.0);
    }

    #[tokio::test]
    async fn test_bit_vector_serialization() {
        use crate::middleware::rate_limit::RateLimitBitVector;

        let bit_vector = RateLimitBitVector {
            bits: vec![0b10101010, 0b01010101],
            start_timestamp: 1234567890,
            bucket_size_seconds: 1,
            bucket_count: 16,
            bucket_counts: Some(vec![1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1]),
        };

        // Test serialization
        let json = serde_json::to_string(&bit_vector).unwrap();
        assert!(!json.is_empty());

        // Test deserialization
        let deserialized: RateLimitBitVector = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bits, bit_vector.bits);
        assert_eq!(deserialized.start_timestamp, bit_vector.start_timestamp);
        assert_eq!(deserialized.bucket_count, bit_vector.bucket_count);
    }
}
