/**
 * Agent Dynamic Access Test Suite
 * 
 * Tests for context-dependent access needs:
 * - Context-dependent permission requests
 * - Just-in-Time (JIT) access scenarios
 * - Dynamic scope expansion
 * - Context-aware access decisions
 */

import { AgentAccessControlTester, DynamicAccessTest } from '../agent-access-control-tester';
import { AccessControlConfig, Resource, Context } from '../../core/types';
import { TestResult } from '../../core/types';

export interface AgentDynamicAccessTestSuiteConfig {
  accessControlConfig: AccessControlConfig;
}

export class AgentDynamicAccessTestSuite {
  private accessControlTester: AgentAccessControlTester;
  private config: AgentDynamicAccessTestSuiteConfig;

  constructor(config: AgentDynamicAccessTestSuiteConfig) {
    this.config = config;
    this.accessControlTester = new AgentAccessControlTester(
      config.accessControlConfig
    );
  }

  /**
   * Test context-dependent permission request
   */
  async testContextDependentPermission(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    context: Context,
    requestedPermission: string,
    expectedGranted: boolean
  ): Promise<TestResult> {
    const test: DynamicAccessTest = {
      agentId,
      agentType,
      userContext,
      scenarios: [
        {
          name: `Context-Dependent Permission - ${requestedPermission}`,
          context,
          requestedPermission,
          expectedGranted,
        },
      ],
    };

    const results = await this.accessControlTester.testDynamicAccess(test);
    const result = results[0];

    return {
      testType: 'agent-dynamic-access',
      testName: `Context-Dependent Permission Test - ${requestedPermission}`,
      passed: result.passed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        context,
        requestedPermission,
        allowed: result.allowed,
        expectedGranted,
        contextAwareDecision: result.contextAwareDecision,
      },
    };
  }

  /**
   * Test Just-in-Time (JIT) access scenario
   */
  async testJITAccess(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    requestedPermission: string,
    context: Context
  ): Promise<TestResult> {
    const test: DynamicAccessTest = {
      agentId,
      agentType,
      userContext,
      scenarios: [
        {
          name: `JIT Access - ${requestedPermission}`,
          context,
          requestedPermission,
          expectedGranted: true,
          jitAccess: true,
        },
      ],
    };

    const results = await this.accessControlTester.testDynamicAccess(test);
    const result = results[0];

    return {
      testType: 'agent-dynamic-access',
      testName: `JIT Access Test - ${requestedPermission}`,
      passed: result.passed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        requestedPermission,
        jitAccessGranted: result.details?.jitAccessGranted,
        jitAccessExpected: result.details?.jitAccessExpected,
        context,
      },
    };
  }

  /**
   * Test dynamic scope expansion
   */
  async testDynamicScopeExpansion(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    basePermission: string,
    expandedPermissions: string[],
    context: Context
  ): Promise<TestResult> {
    const scenarios = [
      {
        name: `Base Permission - ${basePermission}`,
        context,
        requestedPermission: basePermission,
        expectedGranted: true,
      },
      ...expandedPermissions.map(permission => ({
        name: `Expanded Permission - ${permission}`,
        context: {
          ...context,
          additionalAttributes: {
            ...context.additionalAttributes,
            scopeExpansion: true,
            basePermission,
          },
        },
        requestedPermission: permission,
        expectedGranted: true,
      })),
    ];

    const test: DynamicAccessTest = {
      agentId,
      agentType,
      userContext,
      scenarios,
    };

    const results = await this.accessControlTester.testDynamicAccess(test);
    const allPassed = results.every(r => r.passed);

    return {
      testType: 'agent-dynamic-access',
      testName: `Dynamic Scope Expansion Test - ${basePermission}`,
      passed: allPassed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        basePermission,
        expandedPermissions,
        allScenariosPassed: allPassed,
        scenarioResults: results.map(r => ({
          name: r.testName,
          passed: r.passed,
          allowed: r.allowed,
        })),
      },
    };
  }

  /**
   * Test context-aware access decision
   */
  async testContextAwareDecision(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    scenarios: Array<{
      name: string;
      context: Context;
      requestedPermission: string;
      expectedGranted: boolean;
    }>
  ): Promise<TestResult> {
    const test: DynamicAccessTest = {
      agentId,
      agentType,
      userContext,
      scenarios,
    };

    const results = await this.accessControlTester.testDynamicAccess(test);
    const allPassed = results.every(r => r.passed);
    const allContextAware = results.every(r => r.contextAwareDecision === true);

    return {
      testType: 'agent-dynamic-access',
      testName: `Context-Aware Decision Test - ${agentId}`,
      passed: allPassed && allContextAware,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        totalScenarios: scenarios.length,
        allPassed,
        allContextAware,
        scenarioResults: results.map(r => ({
          name: r.testName,
          passed: r.passed,
          allowed: r.allowed,
          contextAware: r.contextAwareDecision,
        })),
      },
    };
  }

  /**
   * Test time-based restrictions
   */
  async testTimeBasedRestrictions(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    requestedPermission: string,
    allowedTimeWindow: { start: string; end: string },
    testTimes: string[]
  ): Promise<TestResult> {
    const scenarios = testTimes.map(time => ({
      name: `Time-Based Access - ${time}`,
      context: {
        timeOfDay: time,
      },
      requestedPermission,
      expectedGranted: this.isTimeInWindow(time, allowedTimeWindow),
      timeWindow: allowedTimeWindow,
    }));

    const test: DynamicAccessTest = {
      agentId,
      agentType,
      userContext,
      scenarios,
    };

    const results = await this.accessControlTester.testDynamicAccess(test);
    const allPassed = results.every(r => r.passed);

    return {
      testType: 'agent-dynamic-access',
      testName: `Time-Based Restrictions Test - ${requestedPermission}`,
      passed: allPassed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        requestedPermission,
        allowedTimeWindow,
        testTimes,
        allScenariosPassed: allPassed,
        scenarioResults: results.map((r, i) => ({
          time: testTimes[i],
          expectedGranted: scenarios[i].expectedGranted,
          allowed: r.allowed,
          passed: r.passed,
        })),
      },
    };
  }

  /**
   * Test location-based access
   */
  async testLocationBasedAccess(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    requestedPermission: string,
    allowedLocations: string[],
    testLocations: string[]
  ): Promise<TestResult> {
    const scenarios = testLocations.map(location => ({
      name: `Location-Based Access - ${location}`,
      context: {
        location,
      },
      requestedPermission,
      expectedGranted: allowedLocations.includes(location),
    }));

    const test: DynamicAccessTest = {
      agentId,
      agentType,
      userContext,
      scenarios,
    };

    const results = await this.accessControlTester.testDynamicAccess(test);
    const allPassed = results.every(r => r.passed);

    return {
      testType: 'agent-dynamic-access',
      testName: `Location-Based Access Test - ${requestedPermission}`,
      passed: allPassed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        requestedPermission,
        allowedLocations,
        testLocations,
        allScenariosPassed: allPassed,
        scenarioResults: results.map((r, i) => ({
          location: testLocations[i],
          expectedGranted: scenarios[i].expectedGranted,
          allowed: r.allowed,
          passed: r.passed,
        })),
      },
    };
  }

  /**
   * Run all dynamic access tests
   */
  async runAllTests(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    testPermissions: string[]
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test 1: Context-dependent permissions
    for (const permission of testPermissions.slice(0, 2)) {
      const context: Context = {
        ipAddress: '192.168.1.100',
        timeOfDay: '14:30',
        location: 'office',
      };
      const result = await this.testContextDependentPermission(
        agentId,
        agentType,
        userContext,
        context,
        permission,
        true
      );
      results.push(result);
    }

    // Test 2: JIT access
    for (const permission of testPermissions.slice(0, 1)) {
      const context: Context = {
        jitAccess: true,
      };
      const result = await this.testJITAccess(
        agentId,
        agentType,
        userContext,
        permission,
        context
      );
      results.push(result);
    }

    // Test 3: Time-based restrictions
    if (testPermissions.length > 0) {
      const timeResult = await this.testTimeBasedRestrictions(
        agentId,
        agentType,
        userContext,
        testPermissions[0],
        { start: '08:00', end: '18:00' },
        ['09:00', '12:00', '20:00']
      );
      results.push(timeResult);
    }

    // Test 4: Location-based access
    if (testPermissions.length > 0) {
      const locationResult = await this.testLocationBasedAccess(
        agentId,
        agentType,
        userContext,
        testPermissions[0],
        ['office', 'headquarters'],
        ['office', 'home', 'headquarters']
      );
      results.push(locationResult);
    }

    return results;
  }

  // Private helper methods

  private isTimeInWindow(
    time: string,
    window: { start: string; end: string }
  ): boolean {
    const [timeHours, timeMinutes] = time.split(':').map(Number);
    const [startHours, startMinutes] = window.start.split(':').map(Number);
    const [endHours, endMinutes] = window.end.split(':').map(Number);

    const timeValue = timeHours * 60 + timeMinutes;
    const startValue = startHours * 60 + startMinutes;
    const endValue = endHours * 60 + endMinutes;

    if (startValue <= endValue) {
      return timeValue >= startValue && timeValue <= endValue;
    } else {
      // Window spans midnight
      return timeValue >= startValue || timeValue <= endValue;
    }
  }
}
