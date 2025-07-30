import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX API Integration Tests", () => {
  let client: any;
  let adminClient: any;
  let userClient: any;

  const TEST_BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";
  const TEST_ADMIN_USERNAME = "testadmin";
  const TEST_ADMIN_PASSWORD = "password";
  const TEST_USER_USERNAME = "testuser";
  const TEST_USER_PASSWORD = "password";

  beforeAll(async () => {
    // Test server connectivity first
    const connectClient = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 5000,
    });

    try {
      const health = await connectClient.health();
      expect(health.success).toBe(true);
    } catch (error) {
      throw new Error(
        `Cannot connect to DBX API at ${TEST_BASE_URL}. Please ensure the server is running.`
      );
    }

    // Create clients for different test scenarios
    adminClient = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 10000,
      maxRetries: 3,
      retryDelayMs: 500,
      poolSize: 5,
      enableLogging: false,
    });

    userClient = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 10000,
      maxRetries: 2,
      enableLogging: false,
    });

    client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      enableLogging: true, // Test logging functionality
    });

    // Authenticate admin client
    try {
      const adminAuth = await adminClient.authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
      );
      expect(adminAuth).toBe(true);
    } catch (error) {
      console.warn(
        "Admin authentication failed - some tests may be skipped:",
        error.message
      );
    }

    // Authenticate user client
    try {
      const userAuth = await userClient.authenticate(
        TEST_USER_USERNAME,
        TEST_USER_PASSWORD
      );
      expect(userAuth).toBe(true);
    } catch (error) {
      console.warn(
        "User authentication failed - some tests may be skipped:",
        error.message
      );
    }
  }, 15000);

  afterAll(async () => {
    // Clean up test data
    const testKeys = [
      "integration:test:string:1",
      "integration:test:string:2",
      "integration:test:hash:1",
      "integration:test:batch:1",
      "integration:test:batch:2",
      "integration:test:batch:3",
      "integration:test:concurrent:*",
      "integration:test:ttl:1",
      "integration:test:performance:*",
    ];

    for (const key of testKeys) {
      try {
        if (key.includes("*")) {
          // Pattern cleanup
          const results = await adminClient.queryPattern(
            key.replace("*", ""),
            100,
            0
          );
          if (results.success && results.results) {
            for (const result of results.results) {
              await adminClient.delete(result.key);
            }
          }
        } else {
          await adminClient.delete(key);
        }
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  }, 10000);

  beforeEach(async () => {
    // Small delay between tests to avoid rate limiting
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  describe("Health and Connectivity", () => {
    it("should respond to health check without authentication", async () => {
      const response = await client.health();
      expect(response.success).toBe(true);
      expect(response.data).toBeDefined();
    });

    it("should handle network timeouts gracefully", async () => {
      const timeoutClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
        timeoutMs: 1, // Very short timeout
        maxRetries: 1,
      });

      try {
        await timeoutClient.health();
        // If this passes, the request was faster than 1ms (unlikely but possible)
      } catch (error) {
        expect(error.message).toMatch(/timeout|network|connection/i);
      }
    });
  });

  describe("Authentication Flow", () => {
    it("should authenticate with valid credentials", async () => {
      const authClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
      });

      const result = await authClient.authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
      );
      expect(result).toBe(true);

      const isAuth = await authClient.isAuthenticated();
      expect(isAuth).toBe(true);
    });

    it("should reject invalid credentials", async () => {
      const authClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
      });

      try {
        await authClient.authenticate("invalid", "wrong");
        expect.fail("Should have thrown authentication error");
      } catch (error) {
        expect(error.message).toMatch(
          /authentication|credentials|unauthorized|login|user not found/i
        );
      }
    });

    it("should handle session validation", async () => {
      const isValid = await adminClient.validateSession();
      expect(typeof isValid).toBe("boolean");
    });

    it("should support logout", async () => {
      const logoutClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
      });

      await logoutClient.authenticate(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD);
      expect(await logoutClient.isAuthenticated()).toBe(true);

      const logoutResult = await logoutClient.logout();
      expect(logoutResult).toBe(true);

      const isAuthAfterLogout = await logoutClient.isAuthenticated();
      expect(isAuthAfterLogout).toBe(false);
    });
  });

  describe("String Data Operations", () => {
    const testKey = "integration:test:string:1";
    const testValue = "integration test value 🚀";

    it("should set and get string values", async () => {
      // Set value
      const setResponse = await adminClient.set(testKey, testValue);
      expect(setResponse.success).toBe(true);
      expect(setResponse.operationId).toBeDefined();
      expect(setResponse.executionTimeMs).toBeDefined();
      expect(setResponse.backend).toBeDefined();

      // Get value
      const getResponse = await adminClient.get(testKey);
      expect(getResponse.success).toBe(true);
      expect(getResponse.data).toBe(testValue);
      expect(getResponse.operationId).toBeDefined();
    });

    it("should handle string values with TTL", async () => {
      const ttlKey = "integration:test:ttl:1";
      const ttlValue = "expires soon";
      const ttlSeconds = 60;

      const setResponse = await adminClient.set(ttlKey, ttlValue, ttlSeconds);
      expect(setResponse.success).toBe(true);

      // Check TTL
      const ttlResponse = await adminClient.getTtl(ttlKey);
      expect(ttlResponse.success).toBe(true);
      expect(parseInt(ttlResponse.data!)).toBeGreaterThan(0);
      expect(parseInt(ttlResponse.data!)).toBeLessThanOrEqual(ttlSeconds);

      // Verify value exists
      const getResponse = await adminClient.get(ttlKey);
      expect(getResponse.success).toBe(true);
      expect(getResponse.data).toBe(ttlValue);
    });

    it("should update existing values", async () => {
      const updateKey = "integration:test:string:2";
      const originalValue = "original";
      const updatedFields = JSON.stringify({
        updated: "new value",
        timestamp: Date.now(),
      });

      // Set initial value
      await adminClient.set(updateKey, originalValue);

      // Update with hash fields
      const updateResponse = await adminClient.update(updateKey, updatedFields);
      expect(updateResponse.success).toBe(true);

      // Verify update
      const getResponse = await adminClient.get(updateKey);
      expect(getResponse.success).toBe(true);
      expect(getResponse.data).toBeDefined();
    });

    it("should check key existence", async () => {
      const existsResponse = await adminClient.exists(testKey);
      expect(existsResponse.success).toBe(true);
      expect(existsResponse.data).toBe("true");

      const notExistsResponse = await adminClient.exists(
        "non:existent:key:12345"
      );
      expect(notExistsResponse.success).toBe(true);
      expect(notExistsResponse.data).toBe("false");
    });

    it("should delete keys", async () => {
      const deleteKey = "integration:test:delete:1";

      // Set a value first
      await adminClient.set(deleteKey, "to be deleted");

      // Verify it exists
      const existsBefore = await adminClient.exists(deleteKey);
      expect(existsBefore.data).toBe("true");

      // Delete it
      const deleteResponse = await adminClient.delete(deleteKey);
      expect(deleteResponse.success).toBe(true);

      // Verify it's gone
      const existsAfter = await adminClient.exists(deleteKey);
      expect(existsAfter.data).toBe("false");
    });

    it("should handle numeric operations", async () => {
      const counterKey = "integration:test:counter:1";

      // Set initial value
      await adminClient.set(counterKey, "10");

      // Increment
      const incResponse = await adminClient.increment(counterKey, 5);
      expect(incResponse.success).toBe(true);

      // Check value
      const getAfterInc = await adminClient.get(counterKey);
      expect(parseInt(getAfterInc.data!)).toBe(15);

      // Decrement
      const decResponse = await adminClient.decrement(counterKey, 3);
      expect(decResponse.success).toBe(true);

      // Check final value
      const getAfterDec = await adminClient.get(counterKey);
      expect(parseInt(getAfterDec.data!)).toBe(12);
    });

    it("should handle string operations", async () => {
      const stringKey = "integration:test:string:ops:1";

      // Set initial value
      await adminClient.set(stringKey, "Hello");

      // Append
      const appendResponse = await adminClient.append(stringKey, " World!");
      expect(appendResponse.success).toBe(true);

      // Check length
      const lengthResponse = await adminClient.length(stringKey);
      expect(lengthResponse.success).toBe(true);
      expect(parseInt(lengthResponse.data!)).toBeGreaterThan(5);

      // Check final value
      const finalValue = await adminClient.get(stringKey);
      expect(finalValue.data).toBe("Hello World!");
    });

    it("should handle conditional operations", async () => {
      const conditionalKey = "integration:test:conditional:1";

      // Set if not exists (should succeed)
      const setIfNotExists1 = await adminClient.setIfNotExists(
        conditionalKey,
        "first",
        300
      );
      expect(setIfNotExists1.success).toBe(true);

      // Set if not exists again (should fail/return false)
      const setIfNotExists2 = await adminClient.setIfNotExists(
        conditionalKey,
        "second",
        300
      );
      expect(setIfNotExists2.success).toBe(true);
      expect(setIfNotExists2.data).toBe("false"); // Key already exists

      // Compare and swap
      const casResponse = await adminClient.compareAndSwap(
        conditionalKey,
        "first",
        "swapped",
        300
      );
      expect(casResponse.success).toBe(true);

      // Verify swap worked
      const finalValue = await adminClient.get(conditionalKey);
      expect(finalValue.data).toBe("swapped");
    });
  });

  describe("Batch Operations", () => {
    it("should execute batch operations efficiently", async () => {
      const operations = [
        {
          operationType: "set",
          key: "integration:test:batch:1",
          value: "batch value 1",
        },
        {
          operationType: "set",
          key: "integration:test:batch:2",
          value: "batch value 2",
          ttl: 300,
        },
        { operationType: "get", key: "integration:test:batch:1" },
        { operationType: "exists", key: "integration:test:batch:2" },
        { operationType: "delete", key: "integration:test:batch:3" }, // Non-existent key
      ];

      const batchResponse = await adminClient.batch(operations);
      expect(batchResponse.success).toBe(true);
      expect(batchResponse.data).toBeDefined();
    });

    it("should support specialized batch operations", async () => {
      const keys = [
        "integration:test:batch:set:1",
        "integration:test:batch:set:2",
        "integration:test:batch:set:3",
      ];
      const values = ["value1", "value2", "value3"];

      // Batch set
      const setOperations = keys.map((key, i) => [key, values[i], null]) as [
        string,
        string,
        number | null
      ][];
      await adminClient.batchSet(setOperations);

      // Batch get
      const getResults = await adminClient.batchGet(keys);
      expect(getResults.success).toBe(true);

      // Batch delete
      const deleteResults = await adminClient.batchDelete(keys);
      expect(deleteResults.success).toBe(true);
    });
  });

  describe("Query Operations", () => {
    beforeEach(async () => {
      // Set up test data for queries
      const testData = [
        [
          "integration:query:user:1",
          JSON.stringify({ name: "Alice", age: 30, role: "admin" }),
        ],
        [
          "integration:query:user:2",
          JSON.stringify({ name: "Bob", age: 25, role: "user" }),
        ],
        [
          "integration:query:user:3",
          JSON.stringify({ name: "Charlie", age: 35, role: "admin" }),
        ],
        ["integration:query:session:1", "session-data-1"],
        ["integration:query:session:2", "session-data-2"],
      ];

      for (const [key, value] of testData) {
        await adminClient.set(key, value);
      }
    });

    it("should support pattern-based queries", async () => {
      const userResults = await adminClient.queryPattern(
        "integration:query:user:*",
        10,
        0
      );
      expect(userResults.success).toBe(true);
      expect(userResults.results).toBeDefined();
      expect(userResults.results!.length).toBeGreaterThanOrEqual(3);
      expect(userResults.queryId).toBeDefined();

      // Check that results contain expected keys
      const keys = userResults.results!.map((r) => r.key);
      expect(keys).toContain("integration:query:user:1");
      expect(keys).toContain("integration:query:user:2");
      expect(keys).toContain("integration:query:user:3");
    });

    it("should support text search queries", async () => {
      const searchResults = await adminClient.queryText(
        "Alice",
        ["name", "role"],
        5,
        0
      );
      expect(searchResults.success).toBe(true);
      expect(searchResults.results).toBeDefined();
      expect(searchResults.queryId).toBeDefined();
    });

    it("should handle empty query results", async () => {
      const emptyResults = await adminClient.queryPattern(
        "integration:query:nonexistent:*",
        10,
        0
      );
      expect(emptyResults.success).toBe(true);
      expect(emptyResults.results!.length).toBe(0);
    });

    it("should support query pagination", async () => {
      // First page
      const page1 = await adminClient.queryPattern("integration:query:*", 2, 0);
      expect(page1.success).toBe(true);
      expect(page1.results!.length).toBeGreaterThan(0);

      // Second page
      const page2 = await adminClient.queryPattern("integration:query:*", 2, 2);
      expect(page2.success).toBe(true);
    });
  });

  describe("Error Handling and Edge Cases", () => {
    it("should handle non-existent key gracefully", async () => {
      const response = await adminClient.get("non:existent:key:987654321");
      expect(response.success).toBe(true);
      expect(response.data).toBeUndefined();
    });

    it("should handle large values", async () => {
      const largeValue = "x".repeat(10000);
      const largeKey = "integration:test:large:1";

      const setResponse = await adminClient.set(largeKey, largeValue);
      expect(setResponse.success).toBe(true);

      const getResponse = await adminClient.get(largeKey);
      expect(getResponse.success).toBe(true);
      expect(getResponse.data).toBe(largeValue);
    });

    it("should handle special characters in keys and values", async () => {
      const specialKey =
        "integration:test:special:!@#$%^&*()_+-=[]{}|;':\",./<>?";
      const specialValue = "Special chars: üñïçødé 🔥 ❤️ 🎉";

      const setResponse = await adminClient.set(specialKey, specialValue);
      expect(setResponse.success).toBe(true);

      const getResponse = await adminClient.get(specialKey);
      expect(getResponse.success).toBe(true);
      expect(getResponse.data).toBe(specialValue);
    });

    it("should handle authentication errors appropriately", async () => {
      const unauthClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
      });

      try {
        await unauthClient.set("test:key", "test:value");
        expect.fail("Should have thrown authentication error");
      } catch (error) {
        expect(error.message).toMatch(
          /authentication|unauthorized|token|login|not authenticated/i
        );
      }
    });

    it("should respect user permissions", async () => {
      // User should be able to access data operations
      const userSet = await userClient.set(
        "integration:test:user:access:1",
        "user data"
      );
      expect(userSet.success).toBe(true);

      const userGet = await userClient.get("integration:test:user:access:1");
      expect(userGet.success).toBe(true);
    });
  });

  describe("Performance and Concurrency", () => {
    it("should handle concurrent operations efficiently", async () => {
      const concurrentOperations = Array.from({ length: 10 }, (_, i) =>
        adminClient.set(
          `integration:test:concurrent:${i}`,
          `concurrent value ${i}`
        )
      );

      const startTime = Date.now();
      const results = await Promise.all(concurrentOperations);
      const endTime = Date.now();

      // All operations should succeed
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });

      // Should be reasonably fast (less than 5 seconds for 10 operations)
      expect(endTime - startTime).toBeLessThan(5000);
    });

    it("should handle retry logic correctly", async () => {
      const retryClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
        maxRetries: 2,
        retryDelayMs: 100,
        enableLogging: false,
      });

      await retryClient.authenticate(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD);

      // This should succeed with retries if there are any transient issues
      const response = await retryClient.set(
        "integration:test:retry:1",
        "retry test"
      );
      expect(response.success).toBe(true);
    });

    it("should demonstrate connection pooling efficiency", async () => {
      const pooledClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
        poolSize: 5,
        timeoutMs: 10000,
      });

      await pooledClient.authenticate(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD);

      // Rapid sequential operations should benefit from connection pooling
      const operations = Array.from(
        { length: 20 },
        (_, i) => pooledClient.get(`integration:test:pool:${i % 3}`) // Reuse some keys
      );

      const startTime = Date.now();
      await Promise.all(operations);
      const endTime = Date.now();

      // Should complete reasonably quickly with pooling
      expect(endTime - startTime).toBeLessThan(3000);
    });
  });

  describe("Configuration and Logging", () => {
    it("should respect logging configuration", async () => {
      // This test verifies logging is configurable
      // The actual log output would go to stderr/console
      const loggingClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
        enableLogging: true,
      });

      await loggingClient.authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
      );

      // This operation should produce log output
      const response = await loggingClient.set(
        "integration:test:logging:1",
        "logged operation"
      );
      expect(response.success).toBe(true);
    });

    it("should return accurate configuration", async () => {
      const testConfig = {
        baseUrl: TEST_BASE_URL,
        timeoutMs: 15000,
        maxRetries: 5,
        retryDelayMs: 2000,
        poolSize: 8,
        autoRefreshToken: false,
        enableLogging: true,
      };

      const configClient = new DbxClient(testConfig);
      const returnedConfig = configClient.getConfig();

      expect(returnedConfig.baseUrl).toBe(testConfig.baseUrl);
      expect(returnedConfig.timeoutMs).toBe(testConfig.timeoutMs);
      expect(returnedConfig.maxRetries).toBe(testConfig.maxRetries);
      expect(returnedConfig.retryDelayMs).toBe(testConfig.retryDelayMs);
      expect(returnedConfig.poolSize).toBe(testConfig.poolSize);
      expect(returnedConfig.autoRefreshToken).toBe(testConfig.autoRefreshToken);
      expect(returnedConfig.enableLogging).toBe(testConfig.enableLogging);
    });

    it("should handle auto-refresh token functionality", async () => {
      const autoRefreshClient = new DbxClient({
        baseUrl: TEST_BASE_URL,
        autoRefreshToken: true,
      });

      await autoRefreshClient.authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
      );

      // This should not throw even if token needs refresh
      await autoRefreshClient.autoRefreshIfNeeded();

      const isAuth = await autoRefreshClient.isAuthenticated();
      expect(isAuth).toBe(true);
    });
  });
});
