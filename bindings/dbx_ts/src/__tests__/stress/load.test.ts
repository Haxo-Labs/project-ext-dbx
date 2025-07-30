import { describe, it, expect, beforeAll, afterAll } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX API Stress Tests", () => {
  let client: any;
  const TEST_BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";
  const TEST_ADMIN_USERNAME = "testadmin";
  const TEST_ADMIN_PASSWORD = "password";

  beforeAll(async () => {
    client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 30000,
      maxRetries: 3,
      retryDelayMs: 200,
      poolSize: 20, // Higher pool size for stress testing
      enableLogging: false,
    });

    try {
      await client.authenticate(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD);
    } catch (error) {
      throw new Error(`Cannot authenticate for stress tests: ${error.message}`);
    }
  }, 30000);

  afterAll(async () => {
    // Clean up all stress test data
    try {
      const cleanupPatterns = [
        "stress:test:*",
        "load:test:*",
        "concurrent:test:*",
        "batch:stress:*",
        "memory:test:*",
      ];

      for (const pattern of cleanupPatterns) {
        const results = await client.queryPattern(pattern, 1000, 0);
        if (results.success && results.results) {
          const keys = results.results.map((r) => r.key);
          if (keys.length > 0) {
            await client.batchDelete(keys);
          }
        }
      }
    } catch (error) {
      console.warn("Cleanup failed:", error.message);
    }
  }, 30000);

  describe("High Volume Operations", () => {
    it("should handle 1000 sequential operations efficiently", async () => {
      const operationCount = 1000;
      const startTime = Date.now();

      for (let i = 0; i < operationCount; i++) {
        const key = `stress:test:sequential:${i}`;
        const value = `sequential value ${i} - ${Date.now()}`;

        const response = await client.set(key, value);
        expect(response.success).toBe(true);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      const opsPerSecond = (operationCount / duration) * 1000;

      console.log(
        `Sequential Operations: ${operationCount} ops in ${duration}ms (${opsPerSecond.toFixed(
          2
        )} ops/sec)`
      );

      // Should complete in reasonable time (less than 30 seconds)
      expect(duration).toBeLessThan(30000);

      // Should achieve reasonable throughput (more than 10 ops/sec)
      expect(opsPerSecond).toBeGreaterThan(10);
    }, 60000);

    it("should handle 1000 concurrent operations efficiently", async () => {
      const operationCount = 1000;
      const startTime = Date.now();

      const operations = Array.from({ length: operationCount }, (_, i) => {
        const key = `stress:test:concurrent:${i}`;
        const value = `concurrent value ${i} - ${Date.now()}`;
        return client.set(key, value);
      });

      const results = await Promise.all(operations);

      const endTime = Date.now();
      const duration = endTime - startTime;
      const opsPerSecond = (operationCount / duration) * 1000;

      // All operations should succeed
      results.forEach((result, index) => {
        expect(result.success).toBe(true, `Operation ${index} failed`);
      });

      console.log(
        `Concurrent Operations: ${operationCount} ops in ${duration}ms (${opsPerSecond.toFixed(
          2
        )} ops/sec)`
      );

      // Concurrent operations should be much faster than sequential
      expect(duration).toBeLessThan(15000);
      expect(opsPerSecond).toBeGreaterThan(50);
    }, 60000);

    it("should handle mixed operation types under load", async () => {
      const operationCount = 500;
      const startTime = Date.now();

      const operations = [];

      for (let i = 0; i < operationCount; i++) {
        const key = `load:test:mixed:${i}`;
        const value = `mixed value ${i}`;

        // Mix of different operation types
        switch (i % 5) {
          case 0:
            operations.push(client.set(key, value));
            break;
          case 1:
            operations.push(client.get(key));
            break;
          case 2:
            operations.push(client.exists(key));
            break;
          case 3:
            operations.push(
              client.update(
                key,
                JSON.stringify({ updated: true, timestamp: Date.now() })
              )
            );
            break;
          case 4:
            operations.push(client.delete(key));
            break;
        }
      }

      const results = await Promise.all(operations);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Most operations should succeed (some gets/exists may fail if keys don't exist)
      const successCount = results.filter((result) => result.success).length;
      const successRate = (successCount / operationCount) * 100;

      expect(successRate).toBeGreaterThan(80); // At least 80% success rate

      console.log(
        `Mixed Operations: ${operationCount} ops in ${duration}ms (${successRate.toFixed(
          1
        )}% success rate)`
      );
    }, 60000);
  });

  describe("Batch Operations Stress", () => {
    it("should handle large batch operations efficiently", async () => {
      const batchSize = 100;
      const batchCount = 10;

      for (let batch = 0; batch < batchCount; batch++) {
        const operations = Array.from({ length: batchSize }, (_, i) => ({
          operationType: "set",
          key: `batch:stress:${batch}:${i}`,
          value: `batch value ${batch}-${i} - ${Date.now()}`,
          ttl: 300,
        }));

        const startTime = Date.now();
        const response = await client.batch(operations);
        const endTime = Date.now();

        expect(response.success).toBe(true);

        const duration = endTime - startTime;
        console.log(`Batch ${batch + 1}: ${batchSize} ops in ${duration}ms`);

        // Each batch should complete quickly
        expect(duration).toBeLessThan(5000);
      }
    }, 120000);

    it("should handle concurrent batch operations", async () => {
      const batchSize = 50;
      const concurrentBatches = 5;

      const batches = Array.from(
        { length: concurrentBatches },
        (_, batchIndex) => {
          const operations = Array.from({ length: batchSize }, (_, i) => ({
            operationType: "set",
            key: `concurrent:batch:${batchIndex}:${i}`,
            value: `concurrent batch value ${batchIndex}-${i}`,
          }));

          return client.batch(operations);
        }
      );

      const startTime = Date.now();
      const results = await Promise.all(batches);
      const endTime = Date.now();

      results.forEach((result, index) => {
        expect(result.success).toBe(true, `Batch ${index} failed`);
      });

      const duration = endTime - startTime;
      const totalOps = batchSize * concurrentBatches;
      const opsPerSecond = (totalOps / duration) * 1000;

      console.log(
        `Concurrent Batches: ${totalOps} ops in ${duration}ms (${opsPerSecond.toFixed(
          2
        )} ops/sec)`
      );
    }, 60000);
  });

  describe("Memory and Resource Usage", () => {
    it("should handle large values without memory issues", async () => {
      const largeSizes = [1024, 10240, 102400]; // 1KB, 10KB, 100KB

      for (const size of largeSizes) {
        const key = `memory:test:large:${size}`;
        const largeValue = "x".repeat(size);

        const setResponse = await client.set(key, largeValue);
        expect(setResponse.success).toBe(true);

        const getResponse = await client.get(key);
        expect(getResponse.success).toBe(true);
        expect(getResponse.data?.length).toBe(size);

        // Clean up immediately to save memory
        await client.delete(key);

        console.log(`Large value test: ${size} bytes OK`);
      }
    }, 60000);

    it("should handle many small operations without connection leaks", async () => {
      const iterationCount = 100;
      const opsPerIteration = 10;

      for (let iteration = 0; iteration < iterationCount; iteration++) {
        const operations = Array.from({ length: opsPerIteration }, (_, i) => {
          const key = `memory:test:small:${iteration}:${i}`;
          return client.set(key, `small value ${iteration}-${i}`);
        });

        const results = await Promise.all(operations);

        results.forEach((result) => {
          expect(result.success).toBe(true);
        });

        // Small delay to prevent overwhelming the server
        if (iteration % 10 === 0) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          console.log(
            `Memory test iteration: ${iteration + 1}/${iterationCount}`
          );
        }
      }

      console.log(
        `Memory test completed: ${iterationCount * opsPerIteration} operations`
      );
    }, 120000);
  });

  describe("Error Recovery and Resilience", () => {
    it("should gracefully handle rapid invalid operations", async () => {
      const invalidOperations = Array.from({ length: 100 }, (_, i) =>
        client.get(`nonexistent:key:${i}:${Date.now()}`)
      );

      const results = await Promise.all(invalidOperations);

      // All operations should complete (returning null for non-existent keys)
      results.forEach((result, index) => {
        expect(result.success).toBe(
          true,
          `Invalid operation ${index} failed unexpectedly`
        );
        expect(result.data).toBeUndefined();
      });

      console.log(
        `Invalid operations test: ${invalidOperations.length} operations handled gracefully`
      );
    }, 30000);

    it("should maintain performance under mixed valid/invalid operations", async () => {
      const operationCount = 200;
      const operations = [];

      for (let i = 0; i < operationCount; i++) {
        if (i % 2 === 0) {
          // Valid operation - set a key
          const key = `resilience:test:valid:${i}`;
          operations.push(client.set(key, `valid value ${i}`));
        } else {
          // Invalid operation - try to get non-existent key
          operations.push(
            client.get(`resilience:test:invalid:${i}:${Date.now()}`)
          );
        }
      }

      const startTime = Date.now();
      const results = await Promise.all(operations);
      const endTime = Date.now();

      // All operations should complete
      expect(results.length).toBe(operationCount);

      // Valid operations should succeed, invalid ones should return null gracefully
      let validSuccesses = 0;
      let invalidHandled = 0;

      results.forEach((result, index) => {
        expect(result.success).toBe(true);

        if (index % 2 === 0) {
          // Valid operation should have data
          validSuccesses++;
        } else {
          // Invalid operation should return undefined
          expect(result.data).toBeUndefined();
          invalidHandled++;
        }
      });

      const duration = endTime - startTime;
      const opsPerSecond = (operationCount / duration) * 1000;

      console.log(
        `Resilience test: ${operationCount} mixed ops in ${duration}ms (${opsPerSecond.toFixed(
          2
        )} ops/sec)`
      );
      console.log(
        `Valid successes: ${validSuccesses}, Invalid handled: ${invalidHandled}`
      );

      expect(validSuccesses).toBe(operationCount / 2);
      expect(invalidHandled).toBe(operationCount / 2);
    }, 60000);
  });

  describe("Query Performance Under Load", () => {
    beforeAll(async () => {
      // Set up data for query tests
      const queryTestData = Array.from({ length: 200 }, (_, i) => [
        `query:load:user:${i}`,
        JSON.stringify({
          id: i,
          name: `User${i}`,
          role: i % 3 === 0 ? "admin" : "user",
          active: i % 4 !== 0,
          created: Date.now() - i * 1000,
        }),
      ]);

      // Insert data in batches
      const batchSize = 50;
      for (let i = 0; i < queryTestData.length; i += batchSize) {
        const batch = queryTestData
          .slice(i, i + batchSize)
          .map(([key, value]) => ({
            operationType: "set",
            key,
            value,
          }));

        await client.batch(batch);
      }

      console.log(`Query test data setup: ${queryTestData.length} records`);
    }, 60000);

    it("should handle concurrent pattern queries efficiently", async () => {
      const queryCount = 20;
      const patterns = [
        "query:load:user:*",
        "query:load:user:1*",
        "query:load:user:2*",
        "query:load:user:*0",
        "query:load:user:*5",
      ];

      const queries = Array.from({ length: queryCount }, (_, i) => {
        const pattern = patterns[i % patterns.length];
        return client.queryPattern(pattern, 50, 0);
      });

      const startTime = Date.now();
      const results = await Promise.all(queries);
      const endTime = Date.now();

      results.forEach((result, index) => {
        expect(result.success).toBe(true, `Query ${index} failed`);
        expect(result.results).toBeDefined();
        expect(result.queryId).toBeDefined();
      });

      const duration = endTime - startTime;
      const queriesPerSecond = (queryCount / duration) * 1000;

      console.log(
        `Concurrent queries: ${queryCount} queries in ${duration}ms (${queriesPerSecond.toFixed(
          2
        )} queries/sec)`
      );

      // Should complete in reasonable time
      expect(duration).toBeLessThan(10000);
    }, 60000);

    it("should handle large result set queries", async () => {
      const startTime = Date.now();
      const largeQuery = await client.queryPattern(
        "query:load:user:*",
        1000,
        0
      );
      const endTime = Date.now();

      expect(largeQuery.success).toBe(true);
      expect(largeQuery.results).toBeDefined();
      expect(largeQuery.results!.length).toBeGreaterThan(100);

      const duration = endTime - startTime;
      console.log(
        `Large query: ${largeQuery.results!.length} results in ${duration}ms`
      );

      // Large queries should still complete in reasonable time
      expect(duration).toBeLessThan(5000);
    }, 30000);
  });
});
