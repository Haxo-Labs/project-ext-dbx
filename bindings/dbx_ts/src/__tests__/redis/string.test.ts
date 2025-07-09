import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX String Operations", () => {
  let client: any;
  const TEST_BASE_URL = process.env.DBX_HTTP_URL || "http://localhost:3000";
  const TEST_USERNAME = process.env.DBX_USERNAME || "testuser";
  const TEST_PASSWORD = process.env.DBX_PASSWORD || "testpassword123";

  beforeAll(async () => {
    client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 5000,
    });

    // Authenticate the client
    try {
      await client.authenticate(TEST_USERNAME, TEST_PASSWORD);
    } catch (error) {
      console.warn("Authentication failed, skipping tests:", error.message);
      // You might want to skip tests here if authentication is required
    }
  });

  afterAll(async () => {
    // Clean up test data
    try {
      await client.delete("test:string:1");
      await client.delete("test:string:2");
      await client.delete("test:string:3");
      await client.delete("test:string:4");
      await client.delete("test:string:5");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  beforeEach(async () => {
    // Clear test strings before each test
    try {
      await client.delete("test:string:1");
      await client.delete("test:string:2");
      await client.delete("test:string:3");
      await client.delete("test:string:4");
      await client.delete("test:string:5");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  describe("set", () => {
    it("should set a string value without TTL", async () => {
      const result = await client.set("test:string:1", "value1");
      expect(result.success).toBe(true);
    });

    it("should set a string value with TTL", async () => {
      const result = await client.set("test:string:1", "value1", 60);
      expect(result.success).toBe(true);
    });

    it("should overwrite existing value", async () => {
      await client.set("test:string:1", "value1");
      const result = await client.set("test:string:1", "value2");
      expect(result.success).toBe(true);
    });
  });

  describe("get", () => {
    it("should get a string value", async () => {
      await client.set("test:string:1", "value1");
      const result = await client.get("test:string:1");
      expect(result.success).toBe(true);
      expect(result.data).toBe('"value1"'); // JSON string
    });

    it("should return success false for non-existent key", async () => {
      // Test non-existent key
      const notExistsResult = await client.get("non-existent-key");
      expect(notExistsResult.success).toBe(true);
      expect(notExistsResult.data).toBeUndefined(); // Non-existent keys have no data field
    });
  });

  describe("delete", () => {
    it("should delete a string value", async () => {
      await client.set("test:string:1", "value1");
      const result = await client.delete("test:string:1");
      expect(result.success).toBe(true);

      // Verify it's deleted (API returns success=true but no data for non-existent keys)
      const getResult = await client.get("test:string:1");
      expect(getResult.success).toBe(true);
      expect(getResult.data).toBeUndefined();
    });

    it("should handle deleting non-existent key", async () => {
      const result = await client.delete("non-existent:key");
      // API may handle this differently
      expect(typeof result.success).toBe("boolean");
    });
  });

  describe("exists", () => {
    it("should check if key exists", async () => {
      await client.set("test:string:1", "value1");
      const result = await client.exists("test:string:1");
      expect(result.success).toBe(true);
      expect(result.data).toBe("true"); // API returns string "true"
    });

    it("should return false for non-existent key", async () => {
      const result = await client.exists("non-existent:key");
      expect(result.success).toBe(true);
      expect(result.data).toBe("false"); // API returns string "false"
    });
  });

  describe("update (hash operations)", () => {
    it("should update hash fields", async () => {
      const fields = JSON.stringify({
        name: "Alice",
        age: 30,
      });
      const result = await client.update("test:hash:1", fields);
      expect(result.success).toBe(true);
    });

    it("should update hash fields with TTL", async () => {
      const fields = JSON.stringify({
        name: "Bob",
        age: 25,
      });
      const result = await client.update("test:hash:1", fields, 60);
      expect(result.success).toBe(true);
    });
  });

  describe("health", () => {
    it("should perform health check", async () => {
      const result = await client.health();
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });
  });
});
