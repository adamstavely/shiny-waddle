/**
 * Access Control Tester Service
 * 
 * Evaluates Policy Decision Point (PDP) decisions for representative
 * identities, attributes, resources, and contexts
 */

import { User, Resource, Context, AccessControlConfig } from '../core/types';
import { PolicyDecisionPoint } from './policy-decision-point';

export interface AccessControlTestInput {
  user: User;
  resource: Resource;
  context: Context;
  expectedDecision?: boolean;
}

export interface AccessControlTestResult {
  allowed: boolean;
  expectedAllowed?: boolean;
  decisionReason: string;
  policyRules: string[];
  timestamp: Date;
  latency?: number;
}

export class AccessControlTester {
  private config: AccessControlConfig;
  private pdp: PolicyDecisionPoint;

  constructor(config: AccessControlConfig) {
    this.config = config;
    this.pdp = new PolicyDecisionPoint(config);
  }

  /**
   * Test a PDP decision for a user accessing a resource in a given context
   */
  async testPDPDecision(input: AccessControlTestInput): Promise<AccessControlTestResult> {
    const startTime = Date.now();

    // Evaluate the policy decision
    // Merge ABAC attributes into subject attributes
    const subjectAttributes = {
      role: input.user.role,
      ...input.user.attributes,
      ...(input.user.abacAttributes || {}),
    };

    const decision = await this.pdp.evaluate({
      subject: {
        id: input.user.id,
        attributes: subjectAttributes,
      },
      resource: {
        id: input.resource.id,
        type: input.resource.type,
        attributes: {
          ...input.resource.attributes,
          ...(input.resource.abacAttributes || {}),
        },
      },
      context: input.context,
    });

    const latency = Date.now() - startTime;

    return {
      allowed: decision.allowed,
      expectedAllowed: input.expectedDecision,
      decisionReason: decision.reason,
      policyRules: decision.appliedRules,
      timestamp: new Date(),
      latency,
    };
  }

  /**
   * Test multiple access scenarios
   */
  async testAccessScenarios(
    scenarios: AccessControlTestInput[]
  ): Promise<AccessControlTestResult[]> {
    const results: AccessControlTestResult[] = [];

    for (const scenario of scenarios) {
      const result = await this.testPDPDecision(scenario);
      results.push(result);
    }

    return results;
  }

  /**
   * Detect policy violations (over-broad queries, missing restrictions)
   */
  async detectPolicyViolations(
    user: User,
    resource: Resource,
    context: Context
  ): Promise<string[]> {
    const violations: string[] = [];
    const decision = await this.pdp.evaluate({
      subject: {
        id: user.id,
        attributes: {
          role: user.role,
          ...user.attributes,
        },
      },
      resource: {
        id: resource.id,
        type: resource.type,
        attributes: resource.attributes,
      },
      context,
    });

    // Check for over-broad access
    if (decision.allowed && resource.sensitivity === 'restricted' && user.role === 'viewer') {
      violations.push('Over-broad access: Viewer accessing restricted resource');
    }

    // Check for missing context restrictions
    if (decision.allowed && !context.ipAddress && resource.sensitivity === 'confidential') {
      violations.push('Missing context restriction: No IP address validation for confidential resource');
    }

    // Check for missing time-based restrictions
    if (decision.allowed && !context.timeOfDay && resource.sensitivity === 'restricted') {
      violations.push('Missing time-based restriction: No time-of-day validation for restricted resource');
    }

    return violations;
  }

  /**
   * Validate that access decisions are consistent
   */
  async validateDecisionConsistency(
    testCases: AccessControlTestInput[]
  ): Promise<{ consistent: boolean; inconsistencies: string[] }> {
    const inconsistencies: string[] = [];
    const results = await this.testAccessScenarios(testCases);

    // Group by user role and resource type
    const groupedResults = new Map<string, AccessControlTestResult[]>();

    for (let i = 0; i < testCases.length; i++) {
      const key = `${testCases[i].user.role}-${testCases[i].resource.type}`;
      if (!groupedResults.has(key)) {
        groupedResults.set(key, []);
      }
      groupedResults.get(key)!.push(results[i]);
    }

    // Check for inconsistencies within groups
    for (const [key, groupResults] of groupedResults) {
      const allowedValues = new Set(groupResults.map(r => r.allowed));
      if (allowedValues.size > 1) {
        inconsistencies.push(
          `Inconsistent decisions for ${key}: found both allowed and denied`
        );
      }
    }

    return {
      consistent: inconsistencies.length === 0,
      inconsistencies,
    };
  }
}

