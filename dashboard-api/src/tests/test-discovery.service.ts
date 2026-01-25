import { Injectable, Logger } from '@nestjs/common';
import { TestEntity } from './entities/test.entity';
import { TestType, TestDomain, APISecurityTest, AccessControlTest, RLSCLSTest } from '../../../heimdall-framework/core/types';
import { getDomainFromTestType } from '../../../heimdall-framework/core/domain-mapping';
import { BaseTestSuite } from '../../../heimdall-framework/services/test-suites/base-test-suite';

// Import test suite classes to discover tests from
import { AuthenticationTestSuite } from '../../../heimdall-framework/services/test-suites/authentication-test-suite';
import { AuthorizationTestSuite } from '../../../heimdall-framework/services/test-suites/authorization-test-suite';
import { InjectionTestSuite } from '../../../heimdall-framework/services/test-suites/injection-test-suite';
import { CryptographyTestSuite } from '../../../heimdall-framework/services/test-suites/cryptography-test-suite';
import { RateLimitingTestSuite } from '../../../heimdall-framework/services/test-suites/rate-limiting-test-suite';
import { SecurityHeadersTestSuite } from '../../../heimdall-framework/services/test-suites/security-headers-test-suite';
import { LoggingTestSuite } from '../../../heimdall-framework/services/test-suites/logging-test-suite';
import { GraphQLTestSuite } from '../../../heimdall-framework/services/test-suites/graphql-test-suite';
import { APIDesignTestSuite } from '../../../heimdall-framework/services/test-suites/api-design-test-suite';
import { ThirdPartyIntegrationTestSuite } from '../../../heimdall-framework/services/test-suites/third-party-integration-test-suite';
import { SensitiveDataTestSuite } from '../../../heimdall-framework/services/test-suites/sensitive-data-test-suite';
import { RLSPolicyTestSuite } from '../../../heimdall-framework/services/test-suites/rls-policy-test-suite';
import { CLSPolicyTestSuite } from '../../../heimdall-framework/services/test-suites/cls-policy-test-suite';
import { EnvironmentConfigTestSuite } from '../../../heimdall-framework/services/test-suites/environment-config-test-suite';
import { BusinessLogicTestSuite } from '../../../heimdall-framework/services/test-suites/business-logic-test-suite';
// Temporarily disabled due to syntax error: import { ABACCorrectnessTestSuite } from '../../../heimdall-framework/services/test-suites/abac-correctness-test-suite';

/**
 * Test Discovery Service
 * 
 * Automatically discovers test definitions from test suite classes in the framework
 */
@Injectable()
export class TestDiscoveryService {
  private readonly logger = new Logger(TestDiscoveryService.name);

  /**
   * Map of test suite classes to their test types
   */
  private readonly testSuiteMap = new Map<typeof BaseTestSuite, { testType: TestType; domain: TestDomain }>([
    [AuthenticationTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [AuthorizationTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [InjectionTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [CryptographyTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [RateLimitingTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [SecurityHeadersTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [LoggingTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [GraphQLTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [APIDesignTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [ThirdPartyIntegrationTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [SensitiveDataTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    [RLSPolicyTestSuite, { testType: 'rls-cls' as TestType, domain: 'identity' as TestDomain }],
    [CLSPolicyTestSuite, { testType: 'rls-cls' as TestType, domain: 'identity' as TestDomain }],
    [EnvironmentConfigTestSuite, { testType: 'environment-config' as TestType, domain: 'platform_config' as TestDomain }],
    [BusinessLogicTestSuite, { testType: 'api-security' as TestType, domain: 'api_security' as TestDomain }],
    // Temporarily disabled: [ABACCorrectnessTestSuite, { testType: 'access-control', domain: 'access_control' }],
  ]);

  /**
   * Discover tests from all test suite classes
   */
  async discoverTests(): Promise<TestEntity[]> {
    const discoveredTests: TestEntity[] = [];

    for (const [TestSuiteClass, { testType, domain }] of this.testSuiteMap) {
      try {
        const tests = this.extractTestsFromSuite(TestSuiteClass, testType, domain);
        discoveredTests.push(...tests);
      } catch (error: any) {
        this.logger.warn(`Failed to discover tests from ${TestSuiteClass.name}: ${error.message}`);
      }
    }

    this.logger.log(`Discovered ${discoveredTests.length} tests from framework`);
    return discoveredTests;
  }

  /**
   * Extract test definitions from a test suite class
   */
  private extractTestsFromSuite(
    TestSuiteClass: any,
    testType: TestType,
    domain: TestDomain
  ): TestEntity[] {
    const tests: TestEntity[] = [];
    const prototype = TestSuiteClass.prototype;
    const suiteName = TestSuiteClass.name.replace('TestSuite', '').replace('Suite', '');

    // Get all method names from the prototype
    const methodNames = Object.getOwnPropertyNames(prototype).filter(
      name => name.startsWith('test') && typeof prototype[name] === 'function'
    );

    for (const methodName of methodNames) {
      try {
        const testEntity = this.createTestFromMethod(methodName, testType, domain, suiteName);
        if (testEntity) {
          tests.push(testEntity);
        }
      } catch (error: any) {
        this.logger.debug(`Failed to create test from ${methodName}: ${error.message}`);
      }
    }

    return tests;
  }

  /**
   * Create a TestEntity from a test method name
   */
  private createTestFromMethod(
    methodName: string,
    testType: TestType,
    domain: TestDomain,
    suiteName: string
  ): TestEntity | null {
    // Convert method name to test name
    // e.g., "testMissingAuthentication" -> "Missing Authentication"
    const testName = methodName
      .replace(/^test/, '')
      .replace(/([A-Z])/g, ' $1')
      .trim();

    // Generate test ID
    const testId = `test.${suiteName.toLowerCase()}.${methodName.replace(/^test/, '').toLowerCase().replace(/([A-Z])/g, '_$1').toLowerCase()}`;

    // Create base test entity
    const testEntity: TestEntity = {
      id: testId,
      name: testName,
      description: `Automatically discovered test from ${suiteName} test suite`,
      testType,
      domain,
      version: 1,
      versionHistory: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'system',
    };

    // Add test-type-specific fields based on testType
    switch (testType) {
      case 'api-security':
        // APISecurityTest has optional fields - we'll create a minimal one
        return {
          ...testEntity,
        } as TestEntity & APISecurityTest;

      case 'access-control':
        return {
          ...testEntity,
          policyId: '',
          inputs: {
            resource: {
              type: '',
              id: '',
              attributes: {},
            },
          },
          expected: {
            allowed: true,
          },
        } as TestEntity & AccessControlTest;

      case 'rls-cls':
        return {
          ...testEntity,
          applicationId: '',
          testQuery: {
            name: testName,
            sql: '',
          },
          expected: {
            rlsEnabled: true,
          },
        } as TestEntity & RLSCLSTest;

      case 'environment-config':
        // Environment config tests use PlatformConfigTest structure
        return {
          ...testEntity,
          platform: 'idp-kubernetes' as const,
          check: '',
        } as any;

      default:
        // For other test types, return base entity
        return testEntity;
    }
  }
}
