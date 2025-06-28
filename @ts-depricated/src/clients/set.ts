import { BaseClient } from "./base";

/**
 * Set client for Redis set operations
 */
export class SetClient extends BaseClient {
  /**
   * Add member to set
   */
  async addMember(key: string, member: string): Promise<number> {
    return this.makeRequest<number>(`${this.baseUrl}/redis/set/${encodeURIComponent(key)}`, {
      method: "POST",
      data: JSON.stringify({ member }),
    });
  }

  /**
   * Remove member from set
   */
  async removeMember(key: string, member: string): Promise<number> {
    return this.makeRequest<number>(
      `${this.baseUrl}/redis/set/${encodeURIComponent(key)}/${encodeURIComponent(member)}`,
      {
        method: "DELETE",
      }
    );
  }

  /**
   * Get set members
   */
  async getMembers(key: string): Promise<string[]> {
    return this.makeRequest<string[]>(
      `${this.baseUrl}/redis/set/${encodeURIComponent(key)}/members`
    );
  }

  /**
   * Check if member exists in set
   */
  async memberExists(key: string, member: string): Promise<boolean> {
    return this.makeRequest<boolean>(
      `${this.baseUrl}/redis/set/${encodeURIComponent(key)}/${encodeURIComponent(member)}/exists`
    );
  }

  /**
   * Get set cardinality (number of members)
   */
  async getCardinality(key: string): Promise<number> {
    return this.makeRequest<number>(
      `${this.baseUrl}/redis/set/${encodeURIComponent(key)}/cardinality`
    );
  }

  /**
   * Intersect sets
   */
  async intersect(keys: string[]): Promise<string[]> {
    return this.makeRequest<string[]>(`${this.baseUrl}/redis/set/intersect`, {
      method: "POST",
      data: JSON.stringify({ keys }),
    });
  }

  /**
   * Union sets
   */
  async union(keys: string[]): Promise<string[]> {
    return this.makeRequest<string[]>(`${this.baseUrl}/redis/set/union`, {
      method: "POST",
      data: JSON.stringify({ keys }),
    });
  }

  /**
   * Difference of sets
   */
  async difference(keys: string[]): Promise<string[]> {
    return this.makeRequest<string[]>(`${this.baseUrl}/redis/set/difference`, {
      method: "POST",
      data: JSON.stringify({ keys }),
    });
  }
}
