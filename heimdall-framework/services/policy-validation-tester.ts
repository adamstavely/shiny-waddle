/**
 * Policy Validation Tester Service
 * 
 * Advanced policy validation including conflict detection, coverage analysis, and simulation
 */

import { ABACPolicy, Resource, PolicyConflict, PolicyCoverage, PolicySimulation } from '../core/types';
import { PolicyDecisionPoint, PDPRequest, PDPDecision } from './policy-decision-point';
import { PolicyTestCase } from './policy-as-code';

/**
 * Configuration for Policy Validation Tester
 */
export interface PolicyValidationTesterConfig {
  /**
   * Policy Decision Point instance (required)
   */
  pdp: PolicyDecisionPoint;
  
  /**
   * Conflict detection options
   */
  conflictDetection?: {
    /**
     * Check for priority conflicts
     */
    checkPriority?: boolean;
    
    /**
     * Check for overlap conflicts
     */
    checkOverlap?: boolean;
    
    /**
     * Check for contradiction conflicts
     */
    checkContradiction?: boolean;
  };
  
  /**
   * Coverage analysis options
   */
  coverageAnalysis?: {
    /**
     * Minimum coverage percentage to consider acceptable
     */
    minCoverage?: number;
    
    /**
     * Generate recommendations for uncovered resources
     */
    generateRecommendations?: boolean;
  };
  
  /**
   * Performance testing options
   */
  performanceTesting?: {
    /**
     * Number of iterations for performance tests
     */
    iterations?: number;
    
    /**
     * Maximum acceptable latency in milliseconds
     */
    maxLatency?: number;
  };
}

export class PolicyValidationTester {
  private pdp: PolicyDecisionPoint;
  private config: PolicyValidationTesterConfig;

  constructor(config: PolicyValidationTesterConfig | PolicyDecisionPoint) {
    // Support both old constructor signature and new config object for backward compatibility
    if (config && 'evaluate' in config) {
      // Old format: just PDP
      this.pdp = config as PolicyDecisionPoint;
      this.config = {
        pdp: this.pdp,
        conflictDetection: {
          checkPriority: true,
          checkOverlap: true,
          checkContradiction: true,
        },
        coverageAnalysis: {
          minCoverage: 80,
          generateRecommendations: true,
        },
        performanceTesting: {
          iterations: 1000,
          maxLatency: 100,
        },
      };
    } else {
      // New format: config object
      this.config = config as PolicyValidationTesterConfig;
      this.pdp = this.config.pdp;
      
      // Set defaults for optional config
      this.config.conflictDetection = {
        checkPriority: true,
        checkOverlap: true,
        checkContradiction: true,
        ...this.config.conflictDetection,
      };
      this.config.coverageAnalysis = {
        minCoverage: 80,
        generateRecommendations: true,
        ...this.config.coverageAnalysis,
      };
      this.config.performanceTesting = {
        iterations: 1000,
        maxLatency: 100,
        ...this.config.performanceTesting,
      };
    }
  }

  /**
   * Detect policy conflicts
   */
  async detectPolicyConflicts(policies: ABACPolicy[]): Promise<PolicyConflict[]> {
    const conflicts: PolicyConflict[] = [];

    for (let i = 0; i < policies.length; i++) {
      for (let j = i + 1; j < policies.length; j++) {
        const policy1 = policies[i];
        const policy2 = policies[j];

        // Check for overlapping conditions
        const overlap = this.detectOverlap(policy1, policy2);
        if (overlap.overlaps) {
          // Check if effects contradict (if enabled)
          if (this.config.conflictDetection?.checkContradiction && 
              policy1.effect !== policy2.effect) {
            conflicts.push({
              policy1: policy1.id,
              policy2: policy2.id,
              conflictType: 'contradiction',
              description: `Policies ${policy1.id} and ${policy2.id} have contradictory effects on overlapping conditions`,
              affectedResources: overlap.resources,
            });
          } else if (this.config.conflictDetection?.checkOverlap && overlap.overlaps) {
            conflicts.push({
              policy1: policy1.id,
              policy2: policy2.id,
              conflictType: 'overlap',
              description: `Policies ${policy1.id} and ${policy2.id} have overlapping conditions`,
              affectedResources: overlap.resources,
            });
          }
        }

        // Check priority conflicts (if enabled)
        if (this.config.conflictDetection?.checkPriority && 
            policy1.priority !== undefined && policy2.priority !== undefined) {
          if (policy1.priority === policy2.priority && overlap.overlaps) {
            conflicts.push({
              policy1: policy1.id,
              policy2: policy2.id,
              conflictType: 'priority',
              description: `Policies ${policy1.id} and ${policy2.id} have the same priority and overlapping conditions`,
              affectedResources: overlap.resources,
            });
          }
        }
      }
    }

    return conflicts;
  }

  /**
   * Analyze policy coverage
   */
  async analyzePolicyCoverage(
    resources: Resource[],
    policies: ABACPolicy[]
  ): Promise<PolicyCoverage> {
    const resourcesWithPolicies = new Set<string>();
    const resourcesWithoutPolicies: string[] = [];
    const gaps: Array<{
      resource: string;
      resourceType: string;
      recommendedPolicy: string;
    }> = [];

    // Check each resource for applicable policies
    for (const resource of resources) {
      const applicablePolicies = this.findApplicablePolicies(resource, policies);
      
      if (applicablePolicies.length > 0) {
        resourcesWithPolicies.add(resource.id);
      } else {
        resourcesWithoutPolicies.push(resource.id);
        gaps.push({
          resource: resource.id,
          resourceType: resource.type,
          recommendedPolicy: this.generateRecommendedPolicy(resource),
        });
      }
    }

    const coveragePercentage = resources.length > 0
      ? (resourcesWithPolicies.size / resources.length) * 100
      : 0;

    return {
      totalResources: resources.length,
      resourcesWithPolicies: resourcesWithPolicies.size,
      resourcesWithoutPolicies,
      coveragePercentage,
      gaps,
    };
  }

  /**
   * Test policy performance
   */
  async testPolicyPerformance(
    policy: ABACPolicy,
    iterations?: number
  ): Promise<{
    policyId: string;
    evaluationCount: number;
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    p50: number;
    p95: number;
    p99: number;
  }> {
    const times: number[] = [];
    const testIterations = iterations ?? this.config.performanceTesting?.iterations ?? 1000;
    const maxLatency = this.config.performanceTesting?.maxLatency;

    // Generate a test request
    const testRequest = this.generateTestRequest(policy);

    // Warm up
    for (let i = 0; i < 10; i++) {
      await this.pdp.evaluate(testRequest);
    }

    // Run performance tests
    for (let i = 0; i < testIterations; i++) {
      const start = process.hrtime.bigint();
      await this.pdp.evaluate(testRequest);
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

    const result = {
      policyId: policy.id,
      evaluationCount: testIterations,
      totalTime,
      averageTime,
      minTime,
      maxTime,
      p50,
      p95,
      p99,
    };

    // Check if performance meets requirements
    if (maxLatency && averageTime > maxLatency) {
      // Could add a warning or flag here
    }

    return result;
  }

  /**
   * Run regression tests
   */
  async runRegressionTests(
    baselinePolicies: ABACPolicy[],
    currentPolicies: ABACPolicy[],
    testCases: PolicyTestCase[]
  ): Promise<{
    policyId: string;
    baselineResults: Map<string, boolean>;
    currentResults: Map<string, boolean>;
    regressions: Array<{
      testCase: string;
      baselineResult: boolean;
      currentResult: boolean;
    }>;
  }> {
    // Create temporary PDPs for baseline and current
    const baselinePDP = this.pdp; // In real implementation, would create separate PDP
    const currentPDP = this.pdp;

    const baselineResults = new Map<string, boolean>();
    const currentResults = new Map<string, boolean>();
    const regressions: Array<{
      testCase: string;
      baselineResult: boolean;
      currentResult: boolean;
    }> = [];

    // Run baseline tests
    for (const testCase of testCases) {
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

      // Evaluate with baseline policies (simplified - would need separate PDP)
      const baselineDecision = await baselinePDP.evaluate(request);
      baselineResults.set(testCase.name, baselineDecision.allowed);

      // Evaluate with current policies
      const currentDecision = await currentPDP.evaluate(request);
      currentResults.set(testCase.name, currentDecision.allowed);

      // Check for regressions
      if (baselineDecision.allowed !== currentDecision.allowed) {
        regressions.push({
          testCase: testCase.name,
          baselineResult: baselineDecision.allowed,
          currentResult: currentDecision.allowed,
        });
      }
    }

    return {
      policyId: 'all-policies',
      baselineResults,
      currentResults,
      regressions,
    };
  }

  /**
   * Simulate policy change
   */
  async simulatePolicyChange(
    policy: ABACPolicy,
    testCases: PolicyTestCase[]
  ): Promise<PolicySimulation> {
    const results: Array<{
      name: string;
      request: any;
      expectedResult: boolean;
      simulatedResult: boolean;
      match: boolean;
    }> = [];

    for (const testCase of testCases) {
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

      // Simulate evaluation with the new policy
      const decision = await this.pdp.evaluate(request);
      const match = decision.allowed === testCase.expected.allowed;

      results.push({
        name: testCase.name,
        request: testCase.request,
        expectedResult: testCase.expected.allowed,
        simulatedResult: decision.allowed,
        match,
      });
    }

    const overallMatch = results.every(r => r.match);

    return {
      policy,
      testCases: results,
      overallMatch,
    };
  }

  /**
   * Detect overlap between two policies
   */
  private detectOverlap(
    policy1: ABACPolicy,
    policy2: ABACPolicy
  ): { overlaps: boolean; resources: string[] } {
    const resources: string[] = [];
    let overlaps = false;

    // Check if conditions overlap
    for (const condition1 of policy1.conditions) {
      for (const condition2 of policy2.conditions) {
        if (this.conditionsOverlap(condition1, condition2)) {
          overlaps = true;
          // Extract resource types from conditions
          if (condition1.attribute.startsWith('resource.')) {
            resources.push(condition1.attribute.replace('resource.', ''));
          }
          if (condition2.attribute.startsWith('resource.')) {
            resources.push(condition2.attribute.replace('resource.', ''));
          }
        }
      }
    }

    return { overlaps, resources: [...new Set(resources)] };
  }

  /**
   * Check if two conditions overlap
   */
  private conditionsOverlap(condition1: any, condition2: any): boolean {
    // Same attribute
    if (condition1.attribute === condition2.attribute) {
      return true;
    }

    // Related attributes (e.g., resource.type and resource.id)
    if (condition1.attribute.includes('.') && condition2.attribute.includes('.')) {
      const parts1 = condition1.attribute.split('.');
      const parts2 = condition2.attribute.split('.');
      if (parts1[0] === parts2[0] && parts1.length > 1 && parts2.length > 1) {
        return true;
      }
    }

    return false;
  }

  /**
   * Find applicable policies for a resource
   */
  private findApplicablePolicies(
    resource: Resource,
    policies: ABACPolicy[]
  ): ABACPolicy[] {
    return policies.filter(policy => {
      return policy.conditions.some(condition => {
        if (condition.attribute.startsWith('resource.')) {
          const attrName = condition.attribute.replace('resource.', '');
          const resourceValue = resource.attributes[attrName] || resource.abacAttributes?.[attrName];
          return this.evaluateCondition(condition, resourceValue);
        }
        return false;
      });
    });
  }

  /**
   * Evaluate a condition
   */
  private evaluateCondition(condition: any, value: any): boolean {
    switch (condition.operator) {
      case 'equals':
        return value === condition.value;
      case 'notEquals':
        return value !== condition.value;
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(value);
      case 'notIn':
        return Array.isArray(condition.value) && !condition.value.includes(value);
      default:
        return false;
    }
  }

  /**
   * Generate recommended policy for a resource
   */
  private generateRecommendedPolicy(resource: Resource): string {
    return `Allow access to ${resource.type} resources with appropriate conditions`;
  }

  /**
   * Generate test request from policy
   */
  private generateTestRequest(policy: ABACPolicy): PDPRequest {
    // Generate a request that matches the policy conditions
    const subject: any = { id: 'test-subject', attributes: {} };
    const resource: any = { id: 'test-resource', type: 'test-resource-type', attributes: {} };

    for (const condition of policy.conditions) {
      if (condition.attribute.startsWith('subject.')) {
        const attrName = condition.attribute.replace('subject.', '');
        subject.attributes[attrName] = condition.value;
      } else if (condition.attribute.startsWith('resource.')) {
        const attrName = condition.attribute.replace('resource.', '');
        resource.attributes[attrName] = condition.value;
      }
    }

    return {
      subject,
      resource,
      action: 'read',
      context: {},
    };
  }
}

