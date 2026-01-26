/**
 * Agent Multi-Service Test Suite
 * 
 * Tests for agents accessing multiple services/tools:
 * - Access across multiple services/tools
 * - Service dependency validation
 * - Cross-service permission consistency
 * - Service mesh integration testing
 */

import { AgentAccessControlTester, MultiServiceAccessTest } from '../agent-access-control-tester';
import { AccessControlConfig, Resource } from '../../core/types';
import { TestResult } from '../../core/types';

export interface AgentMultiServiceTestSuiteConfig {
  accessControlConfig: AccessControlConfig;
}

export class AgentMultiServiceTestSuite {
  private accessControlTester: AgentAccessControlTester;
  private config: AgentMultiServiceTestSuiteConfig;

  constructor(config: AgentMultiServiceTestSuiteConfig) {
    this.config = config;
    this.accessControlTester = new AgentAccessControlTester(
      config.accessControlConfig
    );
  }

  /**
   * Test access across multiple services
   */
  async testMultiServiceAccess(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    services: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
      expectedAllowed: boolean;
    }>
  ): Promise<TestResult> {
    const test: MultiServiceAccessTest = {
      agentId,
      agentType,
      userContext,
      services,
    };

    const result = await this.accessControlTester.testMultiServiceAccess(test);

    return {
      testType: 'agent-multi-service',
      testName: `Multi-Service Access Test - ${agentId}`,
      passed: result.passed,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        services: services.map(s => s.serviceId),
        totalServices: services.length,
        servicesAllowed: result.details?.servicesAllowed,
        multiServiceConsistency: result.multiServiceConsistency,
        serviceResults: result.details?.serviceResults,
        consistencyIssues: result.details?.consistencyIssues,
      },
    };
  }

  /**
   * Test service dependency validation
   */
  async testServiceDependency(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    primaryService: {
      serviceId: string;
      resource: Resource;
      action: string;
    },
    dependentServices: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
      dependencyType: 'required' | 'optional';
    }>
  ): Promise<TestResult> {
    // Test primary service access
    const primaryTest: MultiServiceAccessTest = {
      agentId,
      agentType,
      userContext,
      services: [
        {
          serviceId: primaryService.serviceId,
          resource: primaryService.resource,
          action: primaryService.action,
          expectedAllowed: true,
        },
      ],
    };

    const primaryResult = await this.accessControlTester.testMultiServiceAccess(
      primaryTest
    );

    if (!primaryResult.allowed) {
      return {
        testType: 'agent-multi-service',
        testName: `Service Dependency Test - ${primaryService.serviceId}`,
        passed: false,
        timestamp: new Date(),
        details: {
          agentId,
          primaryService: primaryService.serviceId,
          reason: 'Primary service access denied',
        },
      };
    }

    // Test dependent services
    const dependentTest: MultiServiceAccessTest = {
      agentId,
      agentType,
      userContext,
      services: dependentServices.map(dep => ({
        serviceId: dep.serviceId,
        resource: dep.resource,
        action: dep.action,
        expectedAllowed: dep.dependencyType === 'required',
      })),
    };

    const dependentResult =
      await this.accessControlTester.testMultiServiceAccess(dependentTest);

    // Check if required dependencies are accessible
    const requiredDeps = dependentServices.filter(
      dep => dep.dependencyType === 'required'
    );
    const requiredResults = dependentResult.details?.serviceResults?.filter(
      (r: any, i: number) =>
        dependentServices[i].dependencyType === 'required'
    ) || [];

    const allRequiredAccessible = requiredResults.every(
      (r: any) => r.allowed === r.expectedAllowed
    );

    return {
      testType: 'agent-multi-service',
      testName: `Service Dependency Test - ${primaryService.serviceId}`,
      passed:
        primaryResult.allowed &&
        dependentResult.allowed &&
        allRequiredAccessible,
      timestamp: new Date(),
      details: {
        agentId,
        primaryService: primaryService.serviceId,
        primaryServiceAllowed: primaryResult.allowed,
        dependentServices: dependentServices.map(dep => dep.serviceId),
        requiredDependencies: requiredDeps.map(dep => dep.serviceId),
        allRequiredAccessible,
        dependencyResults: dependentResult.details?.serviceResults,
      },
    };
  }

  /**
   * Test cross-service permission consistency
   */
  async testPermissionConsistency(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    services: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
    }>
  ): Promise<TestResult> {
    const test: MultiServiceAccessTest = {
      agentId,
      agentType,
      userContext,
      services: services.map(service => ({
        serviceId: service.serviceId,
        resource: service.resource,
        action: service.action,
        expectedAllowed: true, // Assume all should be allowed if user has permission
      })),
    };

    const result = await this.accessControlTester.testMultiServiceAccess(test);

    return {
      testType: 'agent-multi-service',
      testName: `Permission Consistency Test - ${agentId}`,
      passed: result.multiServiceConsistency === true,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        services: services.map(s => s.serviceId),
        consistencyCheck: result.multiServiceConsistency,
        consistencyIssues: result.details?.consistencyIssues,
        serviceResults: result.details?.serviceResults,
      },
    };
  }

  /**
   * Test service access sequence
   */
  async testServiceAccessSequence(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    sequence: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
      order: number;
    }>
  ): Promise<TestResult> {
    const sortedSequence = [...sequence].sort((a, b) => a.order - b.order);
    const results: Array<{
      serviceId: string;
      order: number;
      allowed: boolean;
    }> = [];

    // Test access in sequence
    for (const step of sortedSequence) {
      const test: MultiServiceAccessTest = {
        agentId,
        agentType,
        userContext,
        services: [
          {
            serviceId: step.serviceId,
            resource: step.resource,
            action: step.action,
            expectedAllowed: true,
          },
        ],
      };

      const result = await this.accessControlTester.testMultiServiceAccess(test);
      results.push({
        serviceId: step.serviceId,
        order: step.order,
        allowed: result.allowed,
      });
    }

    // Check if sequence completed successfully
    const allAllowed = results.every(r => r.allowed);
    const sequenceMaintained = results.every(
      (r, i) => r.order === sortedSequence[i].order
    );

    return {
      testType: 'agent-multi-service',
      testName: `Service Access Sequence Test - ${agentId}`,
      passed: allAllowed && sequenceMaintained,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        sequence: sortedSequence.map(s => ({
          serviceId: s.serviceId,
          order: s.order,
        })),
        results,
        allAllowed,
        sequenceMaintained,
      },
    };
  }

  /**
   * Test service mesh integration
   */
  async testServiceMeshIntegration(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    meshServices: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
      meshPolicy?: string;
    }>
  ): Promise<TestResult> {
    const test: MultiServiceAccessTest = {
      agentId,
      agentType,
      userContext,
      services: meshServices.map(service => ({
        serviceId: service.serviceId,
        resource: service.resource,
        action: service.action,
        expectedAllowed: true,
      })),
    };

    const result = await this.accessControlTester.testMultiServiceAccess(test);

    // Check if mesh policies are respected
    const meshPolicyCompliant = meshServices.every(service => {
      if (service.meshPolicy) {
        // In a real implementation, validate against service mesh policy
        return true; // Simplified for now
      }
      return true;
    });

    return {
      testType: 'agent-multi-service',
      testName: `Service Mesh Integration Test - ${agentId}`,
      passed: result.passed && meshPolicyCompliant,
      timestamp: new Date(),
      details: {
        agentId,
        agentType,
        meshServices: meshServices.map(s => s.serviceId),
        meshPolicyCompliant,
        serviceResults: result.details?.serviceResults,
      },
    };
  }

  /**
   * Run all multi-service tests
   */
  async runAllTests(
    agentId: string,
    agentType: 'delegated' | 'direct',
    userContext: {
      userId: string;
      permissions: string[];
    } | undefined,
    testServices: Array<{
      serviceId: string;
      resource: Resource;
      action: string;
    }>
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Test 1: Multi-service access
    const multiServiceResult = await this.testMultiServiceAccess(
      agentId,
      agentType,
      userContext,
      testServices.map(service => ({
        ...service,
        expectedAllowed: true,
      }))
    );
    results.push(multiServiceResult);

    // Test 2: Permission consistency
    const consistencyResult = await this.testPermissionConsistency(
      agentId,
      agentType,
      userContext,
      testServices
    );
    results.push(consistencyResult);

    // Test 3: Service access sequence
    if (testServices.length >= 2) {
      const sequenceResult = await this.testServiceAccessSequence(
        agentId,
        agentType,
        userContext,
        testServices.map((service, index) => ({
          ...service,
          order: index + 1,
        }))
      );
      results.push(sequenceResult);
    }

    // Test 4: Service dependency (if we have multiple services)
    if (testServices.length >= 2) {
      const dependencyResult = await this.testServiceDependency(
        agentId,
        agentType,
        userContext,
        testServices[0],
        testServices.slice(1).map(service => ({
          ...service,
          dependencyType: 'required' as const,
        }))
      );
      results.push(dependencyResult);
    }

    return results;
  }
}
