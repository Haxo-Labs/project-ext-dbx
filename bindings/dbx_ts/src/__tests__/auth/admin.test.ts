import { describe, it, expect } from "vitest";
const { DbxClient } = require("../../../index.js");

describe("DBX Admin Authentication Tests", () => {
  const TEST_BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";
  const TEST_ADMIN_USERNAME = "testadmin";
  const TEST_ADMIN_PASSWORD = "password";

  it("should authenticate with the default admin user", async () => {
    const client = new DbxClient({
      baseUrl: TEST_BASE_URL,
      timeoutMs: 10000,
      enableLogging: true,
    });

    try {
      const result = await client.authenticate(
        TEST_ADMIN_USERNAME,
        TEST_ADMIN_PASSWORD
      );
      expect(result).toBe(true);
      expect(await client.isAuthenticated()).toBe(true);
    } catch (error) {
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
    } catch (error) {
      throw error;
    }
  });
});
