/**
 * ABAC Correctness Testing Usage Example
 * 
 * Demonstrates how to use the ABAC correctness testing services
 */

import { ABACAttributeValidator, ABACAttribute } from '../services/abac-attribute-validator';
import { ABACCompletenessTester, CompletenessTestConfig } from '../services/abac-completeness-tester';
import { ABACPerformanceTester, PerformanceTestConfig } from '../services/abac-performance-tester';
import { ABACConflictTester, ConflictTestConfig } from '../services/abac-conflict-tester';
import { PolicyDecisionPoint } from '../services/policy-decision-point';
import { ABACPolicy } from '../core/types';
import { ABACCorrectnessTestSuite } from '../services/test-suites/abac-correctness-test-suite';

async function main() {
  // Example 1: Validate ABAC attributes
  console.log('=== Example 1: ABAC Attribute Validation ===');
  const attributeValidator = new ABACAttributeValidator();
  
  const attribute: ABACAttribute = {
    name: 'clearanceLevel',
    type: 'string',
    source: 'ldap',
    validation: [
      {
        type: 'enum',
        value: ['low', 'medium', 'high', 'top-secret'],
      },
    ],
    freshness: {
      maxAge: 24,
      unit: 'hours',
    },
  };

  const attributeResult = await attributeValidator.validateAttributeDefinition(attribute);
  console.log('Attribute Validation Result:', attributeResult);
  console.log(`Passed: ${attributeResult.passed}`);

  // Example 2: Test policy completeness
  console.log('\n=== Example 2: Policy Completeness Test ===');
  const completenessTester = new ABACCompletenessTester();
  
  const policies: ABACPolicy[] = [
    {
      id: 'policy-1',
      name: 'Department Match Policy',
      description: 'Users can access resources from their department',
      effect: 'allow',
      priority: 100,
      conditions: [
        {
          attribute: 'subject.department',
          operator: 'equals',
          value: '{{resource.department}}',
        },
      ],
    },
    {
      id: 'policy-2',
      name: 'Clearance Level Policy',
      description: 'Users must have sufficient clearance',
      effect: 'allow',
      priority: 200,
      conditions: [
        {
          attribute: 'subject.clearanceLevel',
          operator: 'in',
          value: ['high', 'top-secret'],
        },
        {
          attribute: 'resource.dataClassification',
          operator: 'in',
          value: ['confidential', 'restricted'],
          logicalOperator: 'AND',
        },
      ],
    },
  ];

  const completenessConfig: CompletenessTestConfig = {
    resourceTypes: ['dataset', 'report', 'database'],
    userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
    actions: ['read', 'write', 'delete'],
    policies,
  };

  const completenessResult = await completenessTester.testPolicyCompleteness(completenessConfig);
  console.log('Completeness Test Result:', completenessResult);
  console.log(`Passed: ${completenessResult.passed}`);
  console.log(`Coverage - Resource Types: ${completenessResult.coverage.resourceTypes}%`);
  console.log(`Coverage - User Roles: ${completenessResult.coverage.userRoles}%`);

  // Example 3: Test performance
  console.log('\n=== Example 3: ABAC Performance Test ===');
  const pdp = new PolicyDecisionPoint({
    policyEngine: 'custom',
    policyMode: 'abac',
    abacPolicies: policies,
    cacheDecisions: true,
  });

  const performanceTester = new ABACPerformanceTester(pdp);
  
  const performanceConfig: PerformanceTestConfig = {
    policies,
    testRequests: [
      {
        subject: {
          id: 'user-1',
          attributes: {
            role: 'researcher',
            department: 'Research',
            clearanceLevel: 'high',
          },
        },
        resource: {
          id: 'dataset-1',
          type: 'dataset',
          attributes: {
            department: 'Research',
            dataClassification: 'confidential',
          },
        },
        context: {},
        action: 'read',
      },
    ],
    loadConfig: {
      concurrentRequests: 10,
      duration: 5000,
    },
  };

  const performanceResult = await performanceTester.testEvaluationLatency(performanceConfig);
  console.log('Performance Test Result:', performanceResult);
  console.log(`Average Latency: ${performanceResult.averageLatency}ms`);
  console.log(`Throughput: ${performanceResult.throughput} req/s`);

  // Example 4: Detect policy conflicts
  console.log('\n=== Example 4: Policy Conflict Detection ===');
  const conflictTester = new ABACConflictTester(pdp);
  
  const conflictConfig: ConflictTestConfig = {
    policies,
    resolutionStrategy: 'priority',
  };

  const conflictResult = await conflictTester.detectPolicyConflicts(conflictConfig);
  console.log('Conflict Detection Result:', conflictResult);
  console.log(`Passed: ${conflictResult.passed}`);
  console.log(`Conflicts Found: ${conflictResult.conflicts.length}`);

  // Example 5: Run complete test suite
  console.log('\n=== Example 6: Complete Test Suite ===');
  const testSuite = new ABACCorrectnessTestSuite(pdp);
  
  const suiteConfig = {
    attributes: [attribute],
    policies,
    resourceTypes: ['dataset', 'report'],
    userRoles: ['admin', 'researcher'],
    performanceConfig,
  };

  const suiteResults = await testSuite.runAllTests(suiteConfig);
  console.log(`Total Tests: ${suiteResults.length}`);
  console.log(`Passed: ${suiteResults.filter(r => r.passed).length}`);
  console.log(`Failed: ${suiteResults.filter(r => !r.passed).length}`);
}

main().catch(console.error);

