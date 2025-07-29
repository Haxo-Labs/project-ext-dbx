import { describe, it, expect } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DbxClient Unit Tests", () => {
  describe("Configuration Validation", () => {
    it("should create client with valid configuration", () => {
      const config = {
        baseUrl: "http://localhost:3000",
        username: "testuser",
        password: "testpass",
        timeoutMs: 30000,
        maxRetries: 3,
        retryDelayMs: 1000,
        poolSize: 10,
        autoRefreshToken: true,
        enableLogging: false,
      };

      const client = new DbxClient(config);
      expect(client).toBeDefined();

      const clientConfig = client.getConfig();
      expect(clientConfig.baseUrl).toBe("http://localhost:3000");
      expect(clientConfig.timeoutMs).toBe(30000);
      expect(clientConfig.maxRetries).toBe(3);
      expect(clientConfig.retryDelayMs).toBe(1000);
      expect(clientConfig.poolSize).toBe(10);
      expect(clientConfig.autoRefreshToken).toBe(true);
      expect(clientConfig.enableLogging).toBe(false);
    });

    it("should create client with minimal configuration", () => {
      const config = {
        baseUrl: "https://api.example.com",
      };

      const client = new DbxClient(config);
      expect(client).toBeDefined();

      const clientConfig = client.getConfig();
      expect(clientConfig.baseUrl).toBe("https://api.example.com");
      // getConfig returns original config, not defaults - this is correct behavior
      expect(clientConfig.timeoutMs).toBeUndefined();
      expect(clientConfig.maxRetries).toBeUndefined();
      expect(clientConfig.retryDelayMs).toBeUndefined();
      expect(clientConfig.poolSize).toBeUndefined();
      expect(clientConfig.autoRefreshToken).toBeUndefined();
      expect(clientConfig.enableLogging).toBeUndefined();
    });

    it("should create client with API key authentication", () => {
      const config = {
        baseUrl: "http://localhost:3000",
        apiKey: "test-api-key-12345",
        enableLogging: true,
      };

      const client = new DbxClient(config);
      expect(client).toBeDefined();

      const clientConfig = client.getConfig();
      expect(clientConfig.apiKey).toBe("test-api-key-12345");
      expect(clientConfig.enableLogging).toBe(true);
    });

    it("should throw error for invalid base URL", () => {
      expect(() => {
        new DbxClient({ baseUrl: "" });
      }).toThrow();

      expect(() => {
        new DbxClient({ baseUrl: "invalid-url" });
      }).toThrow();
    });

    it("should validate timeout configuration", () => {
      expect(() => {
        new DbxClient({
          baseUrl: "http://localhost:3000",
          timeoutMs: 0,
        });
      }).toThrow();
    });

    it("should validate retry configuration", () => {
      expect(() => {
        new DbxClient({
          baseUrl: "http://localhost:3000",
          maxRetries: 15, // Over limit
        });
      }).toThrow();
    });

    it("should validate pool size configuration", () => {
      expect(() => {
        new DbxClient({
          baseUrl: "http://localhost:3000",
          poolSize: 0,
        });
      }).toThrow();

      expect(() => {
        new DbxClient({
          baseUrl: "http://localhost:3000",
          poolSize: 150, // Over limit
        });
      }).toThrow();
    });
  });

  describe("Authentication State Management", () => {
    it("should start unauthenticated", async () => {
      const client = new DbxClient({
        baseUrl: "http://localhost:3000",
      });

      const isAuth = await client.isAuthenticated();
      expect(isAuth).toBe(false);
    });

    it("should support API key authentication flag", () => {
      const clientWithApiKey = new DbxClient({
        baseUrl: "http://localhost:3000",
        apiKey: "test-key",
      });

      const clientWithoutApiKey = new DbxClient({
        baseUrl: "http://localhost:3000",
      });

      expect(clientWithApiKey.getConfig().apiKey).toBeDefined();
      expect(clientWithoutApiKey.getConfig().apiKey).toBeUndefined();
    });
  });

  describe("Configuration Edge Cases", () => {
    it("should handle HTTPS URLs", () => {
      const client = new DbxClient({
        baseUrl: "https://secure.example.com:8443",
      });

      expect(client.getConfig().baseUrl).toBe(
        "https://secure.example.com:8443"
      );
    });

    it("should handle custom timeouts and retries", () => {
      const client = new DbxClient({
        baseUrl: "http://localhost:3000",
        timeoutMs: 5000,
        maxRetries: 1,
        retryDelayMs: 500,
        poolSize: 5,
      });

      const config = client.getConfig();
      expect(config.timeoutMs).toBe(5000);
      expect(config.maxRetries).toBe(1);
      expect(config.retryDelayMs).toBe(500);
      expect(config.poolSize).toBe(5);
    });

    it("should handle logging configuration", () => {
      const clientWithLogging = new DbxClient({
        baseUrl: "http://localhost:3000",
        enableLogging: true,
      });

      const clientWithoutLogging = new DbxClient({
        baseUrl: "http://localhost:3000",
        enableLogging: false,
      });

      expect(clientWithLogging.getConfig().enableLogging).toBe(true);
      expect(clientWithoutLogging.getConfig().enableLogging).toBe(false);
    });

    it("should handle auto refresh configuration", () => {
      const clientWithAutoRefresh = new DbxClient({
        baseUrl: "http://localhost:3000",
        autoRefreshToken: true,
      });

      const clientWithoutAutoRefresh = new DbxClient({
        baseUrl: "http://localhost:3000",
        autoRefreshToken: false,
      });

      expect(clientWithAutoRefresh.getConfig().autoRefreshToken).toBe(true);
      expect(clientWithoutAutoRefresh.getConfig().autoRefreshToken).toBe(false);
    });
  });
});
