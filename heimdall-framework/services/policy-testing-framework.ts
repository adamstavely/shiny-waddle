/**
 * Enhanced Policy Testing Framework
 * 
 * Comprehensive policy testing with unit tests, regression tests, and performance tests
 */

import { ABACPolicy } from '../core/types';
import { PolicyTestCase, PolicyTestResult } from './policy-as-code';
import { PolicyDecisionPoint, PDPRequest, PDPDecision } from './policy-decision-point';

export interface PolicyTestSuite {
  id: string;
  name: string;
  description?: string;
  policies: ABACPolicy[];
  testCases: PolicyTestCase[];
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyRegressionTest {
  policyId: string;
  baselineResults: Map<string, boolean>; // testCase name -> expected result
  currentResults: Map<string, boolean>;
  regressions: Array<{
    testCase: string;
    baselineResult: boolean;
    currentResult: boolean;
  }>;
}

export interface PolicyPerformanceMetrics {
  policyId: string;
  evaluationCount: number;
  totalTime: number;
  averageTime: number;
  minTime: number;
  maxTime: number;
  p50: number;
  p95: number;
  p99: number;
}

export class PolicyTestingFramework {
  private pdp: PolicyDecisionPoint;

  constructor(pdp: PolicyDecisionPoint) {
    this.pdp = pdp;
  }

  /**
   * Run unit tests for a policy
   */
  async runUnitTests(
    policy: ABACPolicy,
    testCases: PolicyTestCase[]
  ): Promise<PolicyTestResult> {
    const results: PolicyTestCase[] = [];
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const testCase of testCases) {
      try {
        const request: PDPRequest = {
          subject: {
            id: testCase.request.subject.id || 'test-subject',
            attributes: testCase.request.subject.attributes || testCase.request.subject,
          },
          resource: {
            id: testCase.request.resource.id || 'test-resource',
            type: testCase.request.resource.type || 'test-resource-type',
            attributes: testCase.request.resource.attributes || testCase.request.resource,
          },
          action: testCase.request.action || 'read',
          context: testCase.request.context || {},
        };

        const decision = await this.pdp.evaluate(request);
        const passed = decision.allowed === testCase.expected.allowed;

        results.push({
          ...testCase,
          actual: {
            allowed: decision.allowed,
            reason: decision.reason,
          },
          passed,
        });

        if (!passed) {
          errors.push(
            `Test "${testCase.name}" failed: expected ${testCase.expected.allowed}, got ${decision.allowed}. Reason: ${decision.reason}`
          );
        } else if (testCase.expected.reason && decision.reason !== testCase.expected.reason) {
          warnings.push(
            `Test "${testCase.name}" passed but reason mismatch: expected "${testCase.expected.reason}", got "${decision.reason}"`
          );
        }
      } catch (error: any) {
        errors.push(`Test "${testCase.name}" error: ${error.message}`);
        results.push({
          ...testCase,
          passed: false,
          actual: { allowed: false, reason: error.message },
        });
      }
    }

    return {
      policyId: policy.id,
      passed: errors.length === 0,
      testCases: results,
      errors,
      warnings,
    };
  }

  /**
   * Run regression tests
   */
  async runRegressionTests(
    policy: ABACPolicy,
    baselineResults: Map<string, boolean>,
    testCases: PolicyTestCase[]
  ): Promise<PolicyRegressionTest> {
    const currentResults = new Map<string, boolean>();
    const regressions: Array<{
      testCase: string;
      baselineResult: boolean;
      currentResult: boolean;
    }> = [];

    // Run current tests
    for (const testCase of testCases) {
      try {
        const request: PDPRequest = {
          subject: {
            id: testCase.request.subject.id || 'test-subject',
            attributes: testCase.request.subject.attributes || testCase.request.subject,
          },
          resource: {
            id: testCase.request.resource.id || 'test-resource',
            type: testCase.request.resource.type || 'test-resource-type',
            attributes: testCase.request.resource.attributes || testCase.request.resource,
          },
          action: testCase.request.action || 'read',
          context: testCase.request.context || {},
        };

        const decision = await this.pdp.evaluate(request);
        currentResults.set(testCase.name, decision.allowed);

        // Check for regressions
        const baselineResult = baselineResults.get(testCase.name);
        if (baselineResult !== undefined && baselineResult !== decision.allowed) {
          regressions.push({
            testCase: testCase.name,
            baselineResult,
            currentResult: decision.allowed,
          });
        }
      } catch (error: any) {
        // Treat errors as failures
        currentResults.set(testCase.name, false);
        const baselineResult = baselineResults.get(testCase.name);
        if (baselineResult !== undefined && baselineResult !== false) {
          regressions.push({
            testCase: testCase.name,
            baselineResult,
            currentResult: false,
          });
        }
      }
    }

    return {
      policyId: policy.id,
      baselineResults,
      currentResults,
      regressions,
    };
  }

  /**
   * Run performance tests
   */
  async runPerformanceTests(
    policy: ABACPolicy,
    testCase: PolicyTestCase,
    iterations: number = 1000
  ): Promise<PolicyPerformanceMetrics> {
    const times: number[] = [];

    const request: PDPRequest = {
      subject: {
        id: testCase.request.subject.id || 'test-subject',
        attributes: testCase.request.subject.attributes || testCase.request.subject,
      },
      resource: {
        id: testCase.request.resource.id || 'test-resource',
        type: testCase.request.resource.type || 'test-resource-type',
        attributes: testCase.request.resource.attributes || testCase.request.resource,
      },
      action: testCase.request.action || 'read',
      context: testCase.request.context || {},
    };

    // Warm up
    for (let i = 0; i < 10; i++) {
      await this.pdp.evaluate(request);
    }

    // Run performance tests
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      await this.pdp.evaluate(request);
      const end = process.hrtime.bigint();
      const timeMs = Number(end - start) / 1_000_000; // Convert to milliseconds
      times.push(timeMs);
    }

    // Calculate metrics
    times.sort((a, b) => a - b);
    const totalTime = times.reduce((sum, t) => sum + t, 0);
    const averageTime = totalTime / times.length;
    const minTime = times[0];
    const maxTime = times[times.length - 1];
    const p50 = times[Math.floor(times.length * 0.5)];
    const p95 = times[Math.floor(times.length * 0.95)];
    const p99 = times[Math.floor(times.length * 0.99)];

    return {
      policyId: policy.id,
      evaluationCount: iterations,
      totalTime,
      averageTime,
      minTime,
      maxTime,
      p50,
      p95,
      p99,
    };
  }

  /**
   * Generate test cases from policy
   */
  generateTestCases(policy: ABACPolicy): PolicyTestCase[] {
    const testCases: PolicyTestCase[] = [];

    // Generate test cases based on policy conditions
    for (const condition of policy.conditions) {
      // Test case: condition matches
      testCases.push({
        name: `${policy.id}-${condition.attribute}-matches`,
        description: `Test that ${condition.attribute} matches condition`,
        request: {
          subject: this.generateSubjectFromCondition(condition),
          resource: this.generateResourceFromCondition(condition),
          action: 'read',
        },
        expected: {
          allowed: policy.effect === 'allow',
        },
        passed: false,
      });

      // Test case: condition doesn't match
      testCases.push({
        name: `${policy.id}-${condition.attribute}-no-match`,
        description: `Test that ${condition.attribute} doesn't match condition`,
        request: {
          subject: this.generateSubjectFromCondition(condition, true),
          resource: this.generateResourceFromCondition(condition, true),
          action: 'read',
        },
        expected: {
          allowed: policy.effect === 'deny',
        },
        passed: false,
      });
    }

    return testCases;
  }

  /**
   * Generate subject from condition (for test case generation)
   */
  private generateSubjectFromCondition(condition: any, negate: boolean = false): any {
    const subject: any = { id: 'test-subject', attributes: {} };

    if (condition.attribute.startsWith('subject.')) {
      const attrName = condition.attribute.replace('subject.', '');
      if (negate) {
        // Generate value that doesn't match
        subject.attributes[attrName] = `not-${condition.value}`;
      } else {
        subject.attributes[attrName] = condition.value;
      }
    }

    return subject;
  }

  /**
   * Generate resource from condition (for test case generation)
   */
  private generateResourceFromCondition(condition: any, negate: boolean = false): any {
    const resource: any = { id: 'test-resource', type: 'test-resource-type', attributes: {} };

    if (condition.attribute.startsWith('resource.')) {
      const attrName = condition.attribute.replace('resource.', '');
      if (negate) {
        resource.attributes[attrName] = `not-${condition.value}`;
      } else {
        resource.attributes[attrName] = condition.value;
      }
    }

    return resource;
  }

  /**
   * Create test suite
   */
  createTestSuite(
    name: string,
    policies: ABACPolicy[],
    testCases: PolicyTestCase[]
  ): PolicyTestSuite {
    return {
      id: `suite-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name,
      policies,
      testCases,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  /**
   * Run test suite
   */
  async runTestSuite(suite: PolicyTestSuite): Promise<{
    suiteId: string;
    results: PolicyTestResult[];
    summary: {
      total: number;
      passed: number;
      failed: number;
      passRate: number;
    };
  }> {
    const results: PolicyTestResult[] = [];

    for (const policy of suite.policies) {
      const policyTestCases = suite.testCases.filter(tc => 
        tc.name.startsWith(policy.id) || suite.testCases.length === 0
      );
      
      if (policyTestCases.length > 0) {
        const result = await this.runUnitTests(policy, policyTestCases);
        results.push(result);
      }
    }

    const total = results.reduce((sum, r) => sum + r.testCases.length, 0);
    const passed = results.reduce((sum, r) => 
      sum + r.testCases.filter(tc => tc.passed).length, 0
    );
    const failed = total - passed;
    const passRate = total > 0 ? (passed / total) * 100 : 0;

    return {
      suiteId: suite.id,
      results,
      summary: {
        total,
        passed,
        failed,
        passRate,
      },
    };
  }
}

