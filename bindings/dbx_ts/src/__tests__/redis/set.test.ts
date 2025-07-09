import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX Set-like Operations", () => {
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
    }
  });

  afterAll(async () => {
    // Clean up test data
    try {
      await client.delete("test:set:1");
      await client.delete("test:set:2");
      await client.delete("test:set:3");
      await client.delete("test:collection:1");
      await client.delete("test:collection:2");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  beforeEach(async () => {
    // Clear test data before each test
    try {
      await client.delete("test:set:1");
      await client.delete("test:set:2");
      await client.delete("test:set:3");
      await client.delete("test:collection:1");
      await client.delete("test:collection:2");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  describe("collection operations", () => {
    it("should store collection data as JSON", async () => {
      const setData = JSON.stringify({
        type: "set",
        members: ["member1", "member2", "member3"],
      });
      const result = await client.set("test:set:1", setData);
      expect(result.success).toBe(true);
    });

    it("should retrieve collection data", async () => {
      // Ensure clean state for this specific test
      await client.delete("test:set:1");

      const setData = JSON.stringify({
        type: "set",
        members: ["redis", "database", "cache"],
      });
      await client.set("test:set:1", setData);

      const result = await client.get("test:set:1");
      expect(result.success).toBe(true);

      const parsed = JSON.parse(result.data || "{}");
      expect(parsed.type).toBe("set");
      expect(parsed.members).toContain("redis");
      expect(parsed.members).toContain("database");
      expect(parsed.members).toContain("cache");
    });

    it("should update collection data", async () => {
      const initialData = JSON.stringify({
        type: "set",
        members: ["member1"],
      });
      await client.set("test:set:1", initialData);

      const updatedData = JSON.stringify({
        type: "set",
        members: ["member1", "member2", "member3"],
      });
      const result = await client.set("test:set:1", updatedData);
      expect(result.success).toBe(true);

      const getResult = await client.get("test:set:1");
      const parsed = JSON.parse(getResult.data || "{}");
      expect(parsed.members).toHaveLength(3);
    });
  });

  describe("hash-like operations using update", () => {
    it("should create hash with multiple fields", async () => {
      const fields = JSON.stringify({
        name: "test-collection",
        type: "set",
        count: 5,
        active: true,
      });
      const result = await client.update("test:collection:1", fields);
      expect(result.success).toBe(true);
    });

    it("should update hash fields with TTL", async () => {
      const fields = JSON.stringify({
        name: "temporary-set",
        type: "set",
        expires: true,
      });
      const result = await client.update("test:collection:1", fields, 60);
      expect(result.success).toBe(true);
    });

    it("should handle complex nested data", async () => {
      const complexData = JSON.stringify({
        metadata: {
          type: "set",
          created: new Date().toISOString(),
          version: "1.0",
        },
        members: ["item1", "item2", "item3"],
        operations: {
          add: ["item4"],
          remove: [],
        },
      });
      const result = await client.update("test:collection:1", complexData);
      expect(result.success).toBe(true);
    });
  });

  describe("existence and cleanup", () => {
    it("should check if collection exists", async () => {
      const setData = JSON.stringify({
        type: "set",
        members: ["exists-test"],
      });
      await client.set("test:set:1", setData);

      const result = await client.exists("test:set:1");
      expect(result.success).toBe(true);
      expect(result.data).toBe("true"); // API returns string "true" for existing keys
    });

    it("should delete collections", async () => {
      const setData = JSON.stringify({
        type: "set",
        members: ["delete-test"],
      });
      await client.set("test:set:1", setData);

      const deleteResult = await client.delete("test:set:1");
      expect(deleteResult.success).toBe(true);

      const existsResult = await client.exists("test:set:1");
      expect(existsResult.success).toBe(true);
      expect(existsResult.data).toBe("false"); // API returns string "false" for non-existent keys
    });
  });

  describe("multiple collections", () => {
    it("should handle multiple sets simultaneously", async () => {
      const set1Data = JSON.stringify({
        type: "set",
        name: "collection1",
        members: ["a", "b", "c"],
      });
      const set2Data = JSON.stringify({
        type: "set",
        name: "collection2",
        members: ["x", "y", "z"],
      });

      const result1 = await client.set("test:set:1", set1Data);
      const result2 = await client.set("test:set:2", set2Data);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);

      const get1 = await client.get("test:set:1");
      const get2 = await client.get("test:set:2");

      expect(get1.success).toBe(true);
      expect(get2.success).toBe(true);

      const parsed1 = JSON.parse(get1.data || "{}");
      const parsed2 = JSON.parse(get2.data || "{}");

      expect(parsed1.name).toBe("collection1");
      expect(parsed2.name).toBe("collection2");
    });
  });
});
