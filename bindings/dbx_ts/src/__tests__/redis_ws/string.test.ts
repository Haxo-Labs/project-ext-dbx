import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX String Operations (Alternative Protocol Test)", () => {
  let client: any;
  const TEST_BASE_URL = process.env.DBX_HTTP_URL || "http://localhost:3000";
  const TEST_USERNAME = process.env.DBX_USERNAME || "testuser";
  const TEST_PASSWORD = process.env.DBX_PASSWORD || "testpassword123";

  beforeAll(async () => {
    try {
      console.log("Creating client with URL:", TEST_BASE_URL);
      client = new DbxClient({
        baseUrl: TEST_BASE_URL,
        timeoutMs: 5000,
      });
      console.log("Client created successfully");

      // Authenticate the client
      await client.authenticate(TEST_USERNAME, TEST_PASSWORD);
      console.log("Authentication successful");
    } catch (error) {
      console.error("Failed to create or authenticate client:", error);
      throw error;
    }
  });

  afterAll(async () => {
    // Clean up test data
    try {
      await client.delete("test:ws:string:1");
      await client.delete("test:ws:string:2");
      await client.delete("test:ws:string:3");
      await client.delete("test:ws:pattern:1");
      await client.delete("test:ws:pattern:2");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  beforeEach(async () => {
    // Clear test strings before each test
    try {
      await client.delete("test:ws:string:1");
      await client.delete("test:ws:string:2");
      await client.delete("test:ws:string:3");
      await client.delete("test:ws:pattern:1");
      await client.delete("test:ws:pattern:2");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  describe("Basic Functionality", () => {
    it("should handle basic client operations", async () => {
      // Test basic client functionality
      console.log("Testing basic client functionality...");

      // Test that the client has the expected methods
      expect(typeof client.set).toBe("function");
      expect(typeof client.get).toBe("function");
      expect(typeof client.delete).toBe("function");
      expect(typeof client.update).toBe("function");
      expect(typeof client.exists).toBe("function");
      expect(typeof client.health).toBe("function");

      console.log("Client methods are available");
    });
  });

  describe("String Operations", () => {
    describe("set", () => {
      it("should set a string value without TTL", async () => {
        const result = await client.set("test:ws:string:1", "value1");
        expect(result.success).toBe(true);
      });

      it("should set a string value with TTL", async () => {
        const result = await client.set("test:ws:string:1", "value1", 60);
        expect(result.success).toBe(true);
      });

      it("should overwrite existing value", async () => {
        await client.set("test:ws:string:1", "value1");
        const result = await client.set("test:ws:string:1", "value2");
        expect(result.success).toBe(true);
      });
    });

    describe("get", () => {
      it("should get a string value", async () => {
        await client.set("test:ws:string:1", "value1");
        const result = await client.get("test:ws:string:1");
        expect(result.success).toBe(true);
        expect(result.data).toBe('"value1"'); // JSON string
      });

      it("should return failure for non-existent key", async () => {
        const result = await client.get("non-existent:key");
        expect(result.success).toBe(true);
        expect(result.data).toBeUndefined(); // Non-existent keys have no data field
      });
    });

    describe("delete", () => {
      it("should delete a string value", async () => {
        await client.set("test:ws:string:1", "value1");
        const result = await client.delete("test:ws:string:1");
        expect(result.success).toBe(true);

        // Verify it's deleted (API returns success=true but no data for non-existent keys)
        const getResult = await client.get("test:ws:string:1");
        expect(getResult.success).toBe(true);
        expect(getResult.data).toBeUndefined();
      });

      it("should handle deleting non-existent key", async () => {
        const result = await client.delete("non-existent:key");
        expect(typeof result.success).toBe("boolean");
      });
    });

    describe("update operations", () => {
      it("should update structured data", async () => {
        const fields = JSON.stringify({
          type: "string",
          value: "updated-value",
          metadata: {
            lastModified: new Date().toISOString(),
            version: 2,
          },
        });
        const result = await client.update("test:ws:string:1", fields);
        expect(result.success).toBe(true);
      });

      it("should update with TTL", async () => {
        const fields = JSON.stringify({
          type: "temporary-string",
          value: "expires-soon",
          ttl: 60,
        });
        const result = await client.update("test:ws:string:1", fields, 60);
        expect(result.success).toBe(true);
      });
    });

    describe("batch-like operations", () => {
      it("should handle multiple sequential operations", async () => {
        // Simulate batch operations using sequential calls
        const operations = [
          { key: "test:ws:string:1", value: "value1" },
          { key: "test:ws:string:2", value: "value2" },
          { key: "test:ws:string:3", value: "value3" },
        ];

        for (const op of operations) {
          const result = await client.set(op.key, op.value);
          expect(result.success).toBe(true);
        }

        // Verify all values were set
        for (const op of operations) {
          const result = await client.get(op.key);
          expect(result.success).toBe(true);
          expect(result.data).toBe(`"${op.value}"`);
        }
      });
    });

    describe("pattern-like operations", () => {
      it("should handle pattern-named keys", async () => {
        await client.set("test:ws:pattern:1", "pattern-value-1");
        await client.set("test:ws:pattern:2", "pattern-value-2");
        await client.set("test:ws:other:key", "other-value");

        // Test individual key retrieval
        const result1 = await client.get("test:ws:pattern:1");
        const result2 = await client.get("test:ws:pattern:2");
        const result3 = await client.get("test:ws:other:key");

        expect(result1.success).toBe(true);
        expect(result2.success).toBe(true);
        expect(result3.success).toBe(true);

        expect(result1.data).toBe('"pattern-value-1"');
        expect(result2.data).toBe('"pattern-value-2"');
        expect(result3.data).toBe('"other-value"');
      });
    });
  });

  describe("advanced operations", () => {
    it("should handle complex JSON data", async () => {
      const complexData = JSON.stringify({
        user: {
          id: 123,
          name: "Test User",
          preferences: {
            theme: "dark",
            notifications: true,
          },
        },
        session: {
          id: "session-123",
          expires: new Date(Date.now() + 3600000).toISOString(),
        },
      });

      const result = await client.set("test:ws:string:1", complexData);
      expect(result.success).toBe(true);

      const getResult = await client.get("test:ws:string:1");
      expect(getResult.success).toBe(true);

      const parsed = JSON.parse(getResult.data || "{}");
      expect(parsed.user.name).toBe("Test User");
      expect(parsed.session.id).toBe("session-123");
    });

    it("should handle exists check", async () => {
      await client.set("test:ws:string:1", "exists-test");

      const existsResult = await client.exists("test:ws:string:1");
      expect(existsResult.success).toBe(true);
      expect(existsResult.data).toBe("true"); // API returns string "true" for existing keys

      const notExistsResult = await client.exists("non-existent-key");
      expect(notExistsResult.success).toBe(true);
      expect(notExistsResult.data).toBe("false"); // API returns string "false" for non-existent keys
    });

    it("should handle health check", async () => {
      const result = await client.health();
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });
  });
});
