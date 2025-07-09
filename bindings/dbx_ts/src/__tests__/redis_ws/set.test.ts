import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX Set Operations (Alternative Protocol Test)", () => {
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
      await client.delete("test:ws:set:1");
      await client.delete("test:ws:set:2");
      await client.delete("test:ws:set:3");
      await client.delete("test:ws:collection:1");
      await client.delete("test:ws:collection:2");
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  beforeEach(async () => {
    // Clear test data before each test
    try {
      await client.delete("test:ws:set:1");
      await client.delete("test:ws:set:2");
      await client.delete("test:ws:set:3");
      await client.delete("test:ws:collection:1");
      await client.delete("test:ws:collection:2");
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

  describe("Set Operations (via API)", () => {
    describe("collection storage", () => {
      it("should store set-like data as JSON", async () => {
        const setData = JSON.stringify({
          type: "set",
          members: ["member1", "member2", "member3"],
        });
        const result = await client.set("test:ws:set:1", setData);
        expect(result.success).toBe(true);
      });

      it("should retrieve set-like data", async () => {
        const setData = JSON.stringify({
          type: "set",
          members: ["redis", "websocket", "dbx"],
        });
        await client.set("test:ws:set:1", setData);

        const result = await client.get("test:ws:set:1");
        expect(result.success).toBe(true);

        const parsed = JSON.parse(result.data || "{}");
        expect(parsed.type).toBe("set");
        expect(parsed.members).toContain("redis");
        expect(parsed.members).toContain("websocket");
        expect(parsed.members).toContain("dbx");
      });

      it("should update set membership", async () => {
        const initialData = JSON.stringify({
          type: "set",
          members: ["member1"],
        });
        await client.set("test:ws:set:1", initialData);

        const updatedData = JSON.stringify({
          type: "set",
          members: ["member1", "member2", "member3"],
        });
        const result = await client.set("test:ws:set:1", updatedData);
        expect(result.success).toBe(true);

        const getResult = await client.get("test:ws:set:1");
        const parsed = JSON.parse(getResult.data || "{}");
        expect(parsed.members).toHaveLength(3);
        expect(parsed.members).toContain("member1");
        expect(parsed.members).toContain("member2");
        expect(parsed.members).toContain("member3");
      });
    });

    describe("set operations simulation", () => {
      it("should simulate add operation", async () => {
        // Get existing set or create empty one
        let existingData: { type: string; members: string[] } = {
          type: "set",
          members: [],
        };
        const getResult = await client.get("test:ws:set:1");
        if (getResult.success && getResult.data) {
          try {
            existingData = JSON.parse(getResult.data);
            // Ensure members array exists
            if (!existingData.members || !Array.isArray(existingData.members)) {
              existingData.members = [];
            }
      } catch (error) {
            // If parsing fails, use default empty set
            existingData = { type: "set", members: [] };
          }
        }

        // Add new member
        const newMember = "new-member";
        if (!existingData.members.includes(newMember)) {
          existingData.members.push(newMember);
        }

        const setResult = await client.set(
          "test:ws:set:1",
          JSON.stringify(existingData)
        );
        expect(setResult.success).toBe(true);

        // Verify addition
        const verifyResult = await client.get("test:ws:set:1");
        const parsed = JSON.parse(verifyResult.data || "{}");
        expect(parsed.members).toContain(newMember);
      });

      it("should simulate remove operation", async () => {
        // Setup initial set
        const initialData = JSON.stringify({
          type: "set",
          members: ["member1", "member2", "member3"],
        });
        await client.set("test:ws:set:1", initialData);

        // Remove member
        const getResult = await client.get("test:ws:set:1");
        const setData = JSON.parse(getResult.data || "{}");
        setData.members = setData.members.filter(
          (m: string) => m !== "member2"
        );

        const updateResult = await client.set(
          "test:ws:set:1",
          JSON.stringify(setData)
        );
        expect(updateResult.success).toBe(true);

        // Verify removal
        const verifyResult = await client.get("test:ws:set:1");
        const parsed = JSON.parse(verifyResult.data || "{}");
        expect(parsed.members).not.toContain("member2");
        expect(parsed.members).toContain("member1");
        expect(parsed.members).toContain("member3");
      });

      it("should simulate member existence check", async () => {
        const setData = JSON.stringify({
          type: "set",
          members: ["exists-member", "another-member"],
        });
        await client.set("test:ws:set:1", setData);

        const result = await client.get("test:ws:set:1");
        expect(result.success).toBe(true);

        const parsed = JSON.parse(result.data || "{}");
        const memberExists = parsed.members.includes("exists-member");
        const nonMemberExists = parsed.members.includes("non-existent-member");

        expect(memberExists).toBe(true);
        expect(nonMemberExists).toBe(false);
      });

      it("should simulate cardinality (size) operation", async () => {
        const setData = JSON.stringify({
          type: "set",
          members: ["m1", "m2", "m3", "m4", "m5"],
        });
        await client.set("test:ws:set:1", setData);

        const result = await client.get("test:ws:set:1");
        expect(result.success).toBe(true);

        const parsed = JSON.parse(result.data || "{}");
        const cardinality = parsed.members.length;
        expect(cardinality).toBe(5);
      });
    });

    describe("advanced set operations using update", () => {
      it("should use update for complex set metadata", async () => {
        const setMetadata = JSON.stringify({
          name: "test-set",
          type: "set",
          members: ["member1", "member2"],
          created: new Date().toISOString(),
          operations: {
            additions: 2,
            removals: 0,
          },
        });
        const result = await client.update("test:ws:collection:1", setMetadata);
        expect(result.success).toBe(true);
      });

      it("should handle set operations with TTL", async () => {
        const temporarySet = JSON.stringify({
          type: "temporary-set",
          members: ["temp1", "temp2"],
          expires: true,
        });
        const result = await client.update(
          "test:ws:collection:1",
          temporarySet,
          60
        );
        expect(result.success).toBe(true);
      });
    });

    describe("multiple sets simulation", () => {
      it("should handle multiple sets for set operations", async () => {
        const set1Data = JSON.stringify({
          type: "set",
          name: "set1",
          members: ["a", "b", "c"],
        });
        const set2Data = JSON.stringify({
          type: "set",
          name: "set2",
          members: ["b", "c", "d"],
        });

        const result1 = await client.set("test:ws:set:1", set1Data);
        const result2 = await client.set("test:ws:set:2", set2Data);

        expect(result1.success).toBe(true);
        expect(result2.success).toBe(true);

        // Get both sets
        const get1 = await client.get("test:ws:set:1");
        const get2 = await client.get("test:ws:set:2");

        const parsed1 = JSON.parse(get1.data || "{}");
        const parsed2 = JSON.parse(get2.data || "{}");

        // Simulate intersection
        const intersection = parsed1.members.filter((member: string) =>
          parsed2.members.includes(member)
        );
        expect(intersection).toContain("b");
        expect(intersection).toContain("c");
        expect(intersection).toHaveLength(2);

        // Simulate union
        const union = [...new Set([...parsed1.members, ...parsed2.members])];
        expect(union).toContain("a");
        expect(union).toContain("b");
        expect(union).toContain("c");
        expect(union).toContain("d");
        expect(union).toHaveLength(4);

        // Simulate difference (set1 - set2)
        const difference = parsed1.members.filter(
          (member: string) => !parsed2.members.includes(member)
        );
        expect(difference).toContain("a");
        expect(difference).toHaveLength(1);
      });
    });

    describe("cleanup and existence", () => {
      it("should check set existence", async () => {
        const setData = JSON.stringify({
          type: "set",
          members: ["exists-test"],
        });
        await client.set("test:ws:set:1", setData);

        const result = await client.exists("test:ws:set:1");
        expect(result.success).toBe(true);
      });

      it("should delete sets", async () => {
        const setData = JSON.stringify({
          type: "set",
          members: ["delete-test"],
        });
        await client.set("test:ws:set:1", setData);

        const deleteResult = await client.delete("test:ws:set:1");
        expect(deleteResult.success).toBe(true);

        const existsResult = await client.exists("test:ws:set:1");
        expect(existsResult.success).toBe(true); // API always returns success=true
        expect(existsResult.data).toBe("false"); // API returns string "false" for non-existent keys
      });
    });
  });
});
