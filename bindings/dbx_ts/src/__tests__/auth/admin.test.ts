import { describe, it, expect } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX Admin Authentication Tests", () => {
  const TEST_BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";

  it("should authenticate with the default admin user", async () => {
    const client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 10000,
      enableLogging: true,
    });

    try {
      const result = await client.authenticate("testadmin", "password");
      expect(result).toBe(true);

      const isAuth = await client.isAuthenticated();
      expect(isAuth).toBe(true);

      console.log("✅ Admin authentication successful");
    } catch (error) {
      console.log("❌ Admin authentication failed:", error.message);
      throw error;
    }
  });

  it("should reject authentication with wrong password", async () => {
    const client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 5000,
    });

    try {
      await client.authenticate("testadmin", "wrongpassword");
      expect.fail("Should have thrown authentication error");
    } catch (error) {
      expect(error.message).toMatch(
        /user not found|invalid credentials|authentication/i
      );
      console.log("✅ Wrong password correctly rejected:", error.message);
    }
  });

  it("should be able to perform authenticated operations after login", async () => {
    const client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 10000,
    });

    // First authenticate
    const authResult = await client.authenticate("testadmin", "password");
    expect(authResult).toBe(true);

    // Then try to perform a data operation
    try {
      const setResult = await client.set("admin:test:key", "test value");
      expect(setResult.success).toBe(true);
      console.log("✅ Authenticated data operation successful");
    } catch (error) {
      console.log("❌ Authenticated operation failed:", error.message);
      throw error;
    }
  });
});
