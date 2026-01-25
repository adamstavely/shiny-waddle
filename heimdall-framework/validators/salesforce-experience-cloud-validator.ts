/**
 * Salesforce Experience Cloud Validator
 * 
 * Validator that uses Google's aura-inspector to test Salesforce Experience Cloud
 * applications for security misconfigurations and vulnerabilities.
 * 
 * Reference: https://github.com/google/aura-inspector
 */

import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { TestResult, TestSuite } from '../core/types';
import {
  SalesforceExperienceCloudTester,
  SalesforceExperienceCloudConfig,
  SalesforceExperienceCloudTestResult,
} from '../services/salesforce-experience-cloud-tester';

export class SalesforceExperienceCloudValidator extends BaseValidator {
  readonly id = 'salesforce-experience-cloud';
  readonly name = 'Salesforce Experience Cloud Validator';
  readonly description = 'Tests Salesforce Experience Cloud applications for security misconfigurations using aura-inspector';
  readonly testType = 'salesforce-experience-cloud';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    supportedTestTypes: ['salesforce-experience-cloud'],
    requiredConfig: ['url'],
    optionalConfig: ['cookies', 'objectList', 'app', 'aura', 'context', 'token', 'noGraphQL', 'proxy', 'insecure', 'auraRequestFile'],
    tags: ['salesforce', 'experience-cloud', 'security', 'aura-inspector'],
    exampleConfig: {
      url: 'https://example.force.com',
      cookies: 'sid=...;',
      app: '/myApp',
      aura: '/aura',
      objectList: ['Account', 'Contact'],
    },
  };

  private tester: SalesforceExperienceCloudTester;
  private testerConfig: SalesforceExperienceCloudConfig;

  constructor(config: SalesforceExperienceCloudConfig) {
    super(config);
    this.testerConfig = config;
    this.tester = new SalesforceExperienceCloudTester(config);
  }

  protected shouldRun(suite: TestSuite): boolean {
    // Check if suite test type matches
    return suite.testType === this.testType;
  }

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Get test configuration from suite runtime config or use defaults
    const runtimeConfig = suite.runtimeConfig as any;
    const testConfig: SalesforceExperienceCloudConfig = {
      url: runtimeConfig?.url || this.testerConfig.url,
      cookies: runtimeConfig?.cookies || this.testerConfig.cookies,
      outputDir: runtimeConfig?.outputDir || this.testerConfig.outputDir,
      objectList: runtimeConfig?.objectList || this.testerConfig.objectList,
      app: runtimeConfig?.app || this.testerConfig.app,
      aura: runtimeConfig?.aura || this.testerConfig.aura,
      context: runtimeConfig?.context || this.testerConfig.context,
      token: runtimeConfig?.token || this.testerConfig.token,
      noGraphQL: runtimeConfig?.noGraphQL ?? this.testerConfig.noGraphQL,
      proxy: runtimeConfig?.proxy || this.testerConfig.proxy,
      insecure: runtimeConfig?.insecure ?? this.testerConfig.insecure,
      auraRequestFile: runtimeConfig?.auraRequestFile || this.testerConfig.auraRequestFile,
      auraInspectorPath: runtimeConfig?.auraInspectorPath || this.testerConfig.auraInspectorPath,
      timeout: runtimeConfig?.timeout || this.testerConfig.timeout,
      pythonPath: runtimeConfig?.pythonPath || this.testerConfig.pythonPath,
    };

    // Update tester with new config
    this.tester = new SalesforceExperienceCloudTester(testConfig);

    // Determine which tests to run based on suite configuration
    const testsToRun = runtimeConfig?.testsToRun || [
      'guestAccess',
      'authenticatedAccess',
      'graphQL',
      'selfRegistration',
      'recordLists',
      'homeURLs',
    ];

    // Run requested tests
    for (const testType of testsToRun) {
      try {
        let testResult: SalesforceExperienceCloudTestResult;

        switch (testType) {
          case 'guestAccess':
            testResult = await this.tester.testGuestAccess();
            break;
          case 'authenticatedAccess':
            testResult = await this.tester.testAuthenticatedAccess();
            break;
          case 'graphQL':
            testResult = await this.tester.testGraphQLCapability();
            break;
          case 'selfRegistration':
            testResult = await this.tester.testSelfRegistration();
            break;
          case 'recordLists':
            testResult = await this.tester.testRecordListComponents();
            break;
          case 'homeURLs':
            testResult = await this.tester.testHomeURLs();
            break;
          case 'fullAudit':
            // Full audit returns multiple results
            const auditResults = await this.tester.runFullAudit();
            results.push(...auditResults);
            continue;
          case 'objectAccess':
            // Object access requires object list
            if (testConfig.objectList && testConfig.objectList.length > 0) {
              testResult = await this.tester.testObjectAccess(testConfig.objectList);
            } else {
              results.push(
                this.createFailedResult(
                  'Object Access Test',
                  'objectList is required for object access test',
                  { testType: 'objectAccess' }
                )
              );
              continue;
            }
            break;
          default:
            results.push(
              this.createFailedResult(
                `Unknown test type: ${testType}`,
                `Test type ${testType} is not supported`,
                { testType }
              )
            );
            continue;
        }

        // Convert to TestResult format
        results.push({
          testType: this.testType,
          testName: testResult.testName,
          passed: testResult.passed,
          details: testResult.details,
          timestamp: testResult.timestamp,
          error: testResult.error,
          testId: suite.testIds?.[0], // Use first test ID if available
        });
      } catch (error: any) {
        results.push(
          this.createFailedResult(
            `${testType} Test`,
            error.message,
            {
              testType,
              error: error.message,
              stack: error.stack,
            }
          )
        );
      }
    }

    return results;
  }

  validateConfig(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.url) {
      errors.push('url is required');
    } else {
      try {
        new URL(config.url);
      } catch {
        errors.push('url must be a valid URL');
      }
    }

    // Validate optional configs if provided
    if (config.objectList && !Array.isArray(config.objectList)) {
      errors.push('objectList must be an array');
    }

    if (config.timeout && (typeof config.timeout !== 'number' || config.timeout <= 0)) {
      errors.push('timeout must be a positive number');
    }

    if (config.app && typeof config.app !== 'string') {
      errors.push('app must be a string');
    }

    if (config.aura && typeof config.aura !== 'string') {
      errors.push('aura must be a string');
    }

    if (config.proxy && typeof config.proxy !== 'string') {
      errors.push('proxy must be a string');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
