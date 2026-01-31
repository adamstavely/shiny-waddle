import { Injectable, Logger, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Cache service for policy summaries and other frequently accessed data
 * Uses in-memory cache by default, can be extended to use Redis
 */
@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name);
  private readonly cache: Map<string, { data: any; expiry: number }> = new Map();
  private readonly defaultTTL: number;

  constructor(private readonly configService: ConfigService) {
    // Default TTL: 1 hour (3600 seconds)
    this.defaultTTL = parseInt(
      this.configService.get<string>('CACHE_TTL') || '3600',
      10
    );
    
    // Clean up expired entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  /**
   * Cache a value with optional TTL
   */
  async set(
    key: string,
    value: any,
    ttlSeconds?: number
  ): Promise<void> {
    const ttl = ttlSeconds || this.defaultTTL;
    const expiry = Date.now() + ttl * 1000;

    this.cache.set(key, {
      data: value,
      expiry,
    });

    this.logger.debug(`Cached key: ${key} (TTL: ${ttl}s)`);
  }

  /**
   * Get a cached value
   */
  async get<T>(key: string): Promise<T | null> {
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    // Check if expired
    if (Date.now() > entry.expiry) {
      this.cache.delete(key);
      this.logger.debug(`Cache expired for key: ${key}`);
      return null;
    }

    this.logger.debug(`Cache hit for key: ${key}`);
    return entry.data as T;
  }

  /**
   * Delete a cached value
   */
  async delete(key: string): Promise<void> {
    this.cache.delete(key);
    this.logger.debug(`Deleted cache key: ${key}`);
  }

  /**
   * Delete multiple keys matching a pattern
   */
  async deletePattern(pattern: string): Promise<number> {
    let deleted = 0;
    const regex = new RegExp(pattern.replace('*', '.*'));

    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key);
        deleted++;
      }
    }

    this.logger.debug(`Deleted ${deleted} cache keys matching pattern: ${pattern}`);
    return deleted;
  }

  /**
   * Clear all cache
   */
  async clear(): Promise<void> {
    this.cache.clear();
    this.logger.debug('Cache cleared');
  }

  /**
   * Check if a key exists and is not expired
   */
  async has(key: string): Promise<boolean> {
    const entry = this.cache.get(key);
    if (!entry) {
      return false;
    }

    if (Date.now() > entry.expiry) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Get cache statistics
   */
  getStats(): {
    size: number;
    keys: string[];
    memoryUsage: number;
  } {
    const keys = Array.from(this.cache.keys());
    const memoryUsage = this.estimateMemoryUsage();

    return {
      size: this.cache.size,
      keys,
      memoryUsage,
    };
  }

  /**
   * Cache policy summary with appropriate TTL
   */
  async cacheSummary(
    key: string,
    summary: any,
    ttl: number = 3600 // 1 hour default
  ): Promise<void> {
    await this.set(`summary:${key}`, summary, ttl);
  }

  /**
   * Get cached summary
   */
  async getCachedSummary(key: string): Promise<any | null> {
    return await this.get(`summary:${key}`);
  }

  /**
   * Invalidate cache on policy changes
   */
  async invalidatePolicyCache(policyId: string): Promise<void> {
    // Invalidate all related cache entries
    await this.deletePattern(`summary:*`);
    await this.deletePattern(`policy:${policyId}:*`);
    await this.deletePattern(`compliance:*`);
    await this.deletePattern(`recommendations:${policyId}*`);
    
    this.logger.debug(`Invalidated cache for policy: ${policyId}`);
  }

  /**
   * Cache policy recommendations
   */
  async cacheRecommendations(
    policyId: string,
    recommendations: any[],
    ttl: number = 1800 // 30 minutes default
  ): Promise<void> {
    await this.set(`recommendations:${policyId}`, recommendations, ttl);
  }

  /**
   * Get cached recommendations
   */
  async getCachedRecommendations(policyId: string): Promise<any[] | null> {
    return await this.get(`recommendations:${policyId}`);
  }

  /**
   * Cache compliance analysis
   */
  async cacheComplianceAnalysis(
    analysis: any,
    ttl: number = 1800 // 30 minutes default
  ): Promise<void> {
    await this.set('compliance:analysis', analysis, ttl);
  }

  /**
   * Get cached compliance analysis
   */
  async getCachedComplianceAnalysis(): Promise<any | null> {
    return await this.get('compliance:analysis');
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiry) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.debug(`Cleaned up ${cleaned} expired cache entries`);
    }
  }

  /**
   * Estimate memory usage (rough calculation)
   */
  private estimateMemoryUsage(): number {
    let size = 0;
    for (const [key, value] of this.cache.entries()) {
      size += key.length * 2; // UTF-16 encoding
      size += JSON.stringify(value.data).length * 2;
      size += 16; // Object overhead
    }
    return size;
  }
}
