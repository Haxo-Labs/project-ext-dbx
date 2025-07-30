import { describe, it, expect } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX API Smoke Tests", () => {
  const TEST_BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";

  describe("Basic Connectivity", () => {
    it("should connect to the server and check health", async () => {
      const client = new DbxClient({
        baseUrl: TEST_BASE_URL,
        timeoutMs: 5000,
        enableLogging: true,
      });

      const health = await client.health();
      expect(health.success).toBe(true);
      expect(health.data).toBeDefined();
    });

    it("should handle client configuration correctly", async () => {
      const config = {
        baseUrl: TEST_BASE_URL,
        timeoutMs: 10000,
        maxRetries: 3,
        retryDelayMs: 1000,
        poolSize: 5,
        autoRefreshToken: false,
        enableLogging: false,
      };

      const client = new DbxClient(config);
      const returnedConfig = client.getConfig();

      expect(returnedConfig.baseUrl).toBe(config.baseUrl);
      expect(returnedConfig.timeoutMs).toBe(config.timeoutMs);
      expect(returnedConfig.maxRetries).toBe(config.maxRetries);
      expect(returnedConfig.retryDelayMs).toBe(config.retryDelayMs);
      expect(returnedConfig.poolSize).toBe(config.poolSize);
      expect(returnedConfig.autoRefreshToken).toBe(config.autoRefreshToken);
      expect(returnedConfig.enableLogging).toBe(config.enableLogging);
    });

    it("should handle authentication errors gracefully", async () => {
      const client = new DbxClient({
        baseUrl: TEST_BASE_URL,
        timeoutMs: 5000,
      });

      try {
        await client.set("test:key", "test:value");
        expect.fail("Should have thrown authentication error");
      } catch (error) {
        expect(error.message).toMatch(
          /not authenticated|authentication|unauthorized/i
        );
      }
    });

    it("should handle invalid server URL gracefully", async () => {
      const client = new DbxClient({
        baseUrl: "http://localhost:9999", // Non-existent server
        timeoutMs: 2000,
        maxRetries: 1,
        retryDelayMs: 100,
      });

      try {
        await client.health();
        expect.fail("Should have thrown connection error");
      } catch (error) {
        expect(error.message).toMatch(/network|connection|timeout|refused/i);
      }
    });
  });

  describe("Error Handling", () => {
    it("should validate configuration parameters", async () => {
      // Test invalid configuration
      try {
        new DbxClient({
          baseUrl: "invalid-url",
          timeoutMs: -1,
          maxRetries: -1,
        });
        expect.fail("Should have thrown validation error");
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it("should handle retry logic", async () => {
      const client = new DbxClient({
        baseUrl: "http://localhost:9998", // Non-existent server
        timeoutMs: 500,
        maxRetries: 2,
        retryDelayMs: 100,
        enableLogging: true,
      });

      const startTime = Date.now();

      try {
        await client.health();
        expect.fail("Should have failed after retries");
      } catch (error) {
        const duration = Date.now() - startTime;

        // Should have taken at least as long as: initial attempt + 2 retries + retry delays
        // But less than 10 seconds (reasonable upper bound)
        expect(duration).toBeGreaterThan(200); // At least some retry attempts
        expect(duration).toBeLessThan(10000); // But not forever
      }
    }, 15000);
  });

  describe("API Endpoint Structure", () => {
    it("should expose expected API structure", async () => {
      const client = new DbxClient({
        baseUrl: TEST_BASE_URL,
      });

      // Test that methods exist (even if they fail due to auth)
      expect(typeof client.authenticate).toBe("function");
      expect(typeof client.set).toBe("function");
      expect(typeof client.get).toBe("function");
      expect(typeof client.delete).toBe("function");
      expect(typeof client.exists).toBe("function");
      expect(typeof client.batch).toBe("function");
      expect(typeof client.queryPattern).toBe("function");
      expect(typeof client.queryText).toBe("function");
      expect(typeof client.health).toBe("function");
      expect(typeof client.isAuthenticated).toBe("function");
      expect(typeof client.getConfig).toBe("function");
    });
  });
});
