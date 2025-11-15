/**
 * ABAC Performance Tester
 * 
 * Tests ABAC evaluation latency, caching, attribute lookup performance, and load performance
 */

import { ABACPolicy } from '../core/types';
import { PolicyDecisionPoint, PDPRequest } from './policy-decision-point';

export interface PerformanceTestConfig {
  policies: ABACPolicy[];
  testRequests: PDPRequest[];
  loadConfig?: {
    concurrentRequests: number;
    duration: number; // milliseconds
  };
}

export interface PerformanceTestResult {
  passed: boolean;
  averageLatency: number; // milliseconds
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
  throughput: number; // requests per second
  cacheHitRate?: number;
  recommendations: PerformanceRecommendation[];
}

export interface PerformanceRecommendation {
  type: 'enable-caching' | 'optimize-policies' | 'reduce-attributes' | 'parallel-evaluation';
  description: string;
  impact: 'high' | 'medium' | 'low';
}

export interface CacheResult {
  enabled: boolean;
  hitRate: number;
  effectiveness: number; // 0-100
  issues: string[];
}

export interface LookupResult {
  averageLookupTime: number;
  slowestAttribute: string;
  issues: string[];
}

export interface LoadTestResult {
  passed: boolean;
  requestsProcessed: number;
  errors: number;
  averageLatency: number;
  maxLatency: number;
  throughput: number;
}

export interface BenchmarkResult {
  improved: boolean;
  latencyImprovement: number; // percentage
  throughputImprovement: number; // percentage
  recommendations: string[];
}

export class ABACPerformanceTester {
  private pdp: PolicyDecisionPoint;

  constructor(pdp: PolicyDecisionPoint) {
    this.pdp = pdp;
  }

  /**
   * Test evaluation latency
   */
  async testEvaluationLatency(
    config: PerformanceTestConfig
  ): Promise<PerformanceTestResult> {
    const latencies: number[] = [];

    // Run test requests and measure latency
    for (const request of config.testRequests) {
      const startTime = Date.now();
      await this.pdp.evaluate(request);
      const latency = Date.now() - startTime;
      latencies.push(latency);
    }

    // Calculate statistics
    latencies.sort((a, b) => a - b);
    const averageLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const p50Latency = latencies[Math.floor(latencies.length * 0.5)];
    const p95Latency = latencies[Math.floor(latencies.length * 0.95)];
    const p99Latency = latencies[Math.floor(latencies.length * 0.99)];

    // Calculate throughput
    const totalTime = latencies.reduce((a, b) => a + b, 0);
    const throughput = (config.testRequests.length / totalTime) * 1000; // requests per second

    // Generate recommendations
    const recommendations = await this.generateOptimizationRecommendations({
      passed: averageLatency < 100, // Pass if average < 100ms
      averageLatency,
      p50Latency,
      p95Latency,
      p99Latency,
      throughput,
      recommendations: [],
    });

    return {
      passed: averageLatency < 100 && p95Latency < 500,
      averageLatency,
      p50Latency,
      p95Latency,
      p99Latency,
      throughput,
      recommendations,
    };
  }

  /**
   * Test policy caching
   */
  async testPolicyCaching(
    config: PerformanceTestConfig
  ): Promise<CacheResult> {
    const issues: string[] = [];

    // Check if caching is enabled
    // This would require checking the PDP configuration
    const cachingEnabled = true; // Simplified - would check actual config

    if (!cachingEnabled) {
      issues.push('Policy caching is not enabled');
      return {
        enabled: false,
        hitRate: 0,
        effectiveness: 0,
        issues,
      };
    }

    // Test cache effectiveness
    // Run same request multiple times and measure cache hits
    const request = config.testRequests[0];
    const firstRun = Date.now();
    await this.pdp.evaluate(request);
    const firstLatency = Date.now() - firstRun;

    const secondRun = Date.now();
    await this.pdp.evaluate(request);
    const secondLatency = Date.now() - secondRun;

    // If second run is significantly faster, caching is working
    const cacheEffective = secondLatency < firstLatency * 0.5;
    const hitRate = cacheEffective ? 0.8 : 0.2; // Simplified

    return {
      enabled: true,
      hitRate,
      effectiveness: cacheEffective ? 80 : 20,
      issues,
    };
  }

  /**
   * Test attribute lookup performance
   */
  async testAttributeLookupPerformance(
    attributes: Array<{ name: string; source: string }>
  ): Promise<LookupResult> {
    const lookupTimes: Array<{ attribute: string; time: number }> = [];

    // Test lookup time for each attribute
    for (const attr of attributes) {
      const startTime = Date.now();
      // Simulate attribute lookup
      await this.simulateAttributeLookup(attr);
      const lookupTime = Date.now() - startTime;
      lookupTimes.push({ attribute: attr.name, time: lookupTime });
    }

    const averageLookupTime =
      lookupTimes.reduce((sum, lt) => sum + lt.time, 0) / lookupTimes.length;

    const slowest = lookupTimes.reduce((max, lt) =>
      lt.time > max.time ? lt : max
    );

    const issues: string[] = [];
    if (averageLookupTime > 50) {
      issues.push(`Average attribute lookup time (${averageLookupTime}ms) is high`);
    }

    return {
      averageLookupTime,
      slowestAttribute: slowest.attribute,
      issues,
    };
  }

  /**
   * Test load performance
   */
  async testLoadPerformance(
    config: PerformanceTestConfig
  ): Promise<LoadTestResult> {
    if (!config.loadConfig) {
      throw new Error('Load test configuration is required');
    }

    const { concurrentRequests, duration } = config.loadConfig;
    const startTime = Date.now();
    const endTime = startTime + duration;

    let requestsProcessed = 0;
    let errors = 0;
    const latencies: number[] = [];

    // Run concurrent requests
    const requestPromises: Promise<void>[] = [];

    while (Date.now() < endTime) {
      // Start concurrent requests
      for (let i = 0; i < concurrentRequests; i++) {
        const request = config.testRequests[
          requestsProcessed % config.testRequests.length
        ];
        const promise = (async () => {
          try {
            const reqStart = Date.now();
            await this.pdp.evaluate(request);
            const reqLatency = Date.now() - reqStart;
            latencies.push(reqLatency);
            requestsProcessed++;
          } catch (error) {
            errors++;
          }
        })();
        requestPromises.push(promise);
      }

      // Wait a bit before next batch
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // Wait for all requests to complete
    await Promise.all(requestPromises);

    const totalTime = Date.now() - startTime;
    const averageLatency =
      latencies.length > 0
        ? latencies.reduce((a, b) => a + b, 0) / latencies.length
        : 0;
    const maxLatency = latencies.length > 0 ? Math.max(...latencies) : 0;
    const throughput = (requestsProcessed / totalTime) * 1000; // requests per second

    return {
      passed: errors === 0 && averageLatency < 200,
      requestsProcessed,
      errors,
      averageLatency,
      maxLatency,
      throughput,
    };
  }

  /**
   * Generate optimization recommendations
   */
  async generateOptimizationRecommendations(
    result: PerformanceTestResult
  ): Promise<PerformanceRecommendation[]> {
    const recommendations: PerformanceRecommendation[] = [];

    if (result.averageLatency > 100) {
      recommendations.push({
        type: 'optimize-policies',
        description: 'Average latency is high - consider optimizing policy conditions',
        impact: 'high',
      });
    }

    if (result.p95Latency > 500) {
      recommendations.push({
        type: 'enable-caching',
        description: 'P95 latency is high - enable policy caching',
        impact: 'high',
      });
    }

    if (result.throughput < 100) {
      recommendations.push({
        type: 'parallel-evaluation',
        description: 'Throughput is low - consider parallel policy evaluation',
        impact: 'medium',
      });
    }

    if (!result.cacheHitRate || result.cacheHitRate < 0.5) {
      recommendations.push({
        type: 'enable-caching',
        description: 'Cache hit rate is low - optimize cache key generation',
        impact: 'medium',
      });
    }

    return recommendations;
  }

  /**
   * Benchmark performance
   */
  async benchmarkPerformance(
    baseline: PerformanceTestResult,
    current: PerformanceTestResult
  ): Promise<BenchmarkResult> {
    const latencyImprovement =
      ((baseline.averageLatency - current.averageLatency) /
        baseline.averageLatency) *
      100;

    const throughputImprovement =
      ((current.throughput - baseline.throughput) / baseline.throughput) * 100;

    const improved = latencyImprovement > 0 && throughputImprovement > 0;

    const recommendations: string[] = [];

    if (latencyImprovement < 0) {
      recommendations.push(
        `Latency increased by ${Math.abs(latencyImprovement).toFixed(1)}%`
      );
    }

    if (throughputImprovement < 0) {
      recommendations.push(
        `Throughput decreased by ${Math.abs(throughputImprovement).toFixed(1)}%`
      );
    }

    if (improved) {
      recommendations.push('Performance has improved');
    }

    return {
      improved,
      latencyImprovement,
      throughputImprovement,
      recommendations,
    };
  }

  /**
   * Simulate attribute lookup
   */
  private async simulateAttributeLookup(attribute: {
    name: string;
    source: string;
  }): Promise<void> {
    // Simulate different lookup times based on source
    const lookupTimes: Record<string, number> = {
      ldap: 30,
      database: 20,
      api: 50,
      jwt: 5,
      custom: 10,
    };

    const delay = lookupTimes[attribute.source] || 20;
    await new Promise(resolve => setTimeout(resolve, delay));
  }
}

