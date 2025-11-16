/**
 * Distributed Systems Testing Example
 * 
 * Demonstrates how to test access control and compliance across
 * distributed systems, multi-region deployments, and microservices.
 * 
 * IMPORTANT: All region endpoints and credentials should be provided via
 * runtime configuration (environment variables or config files), not hardcoded.
 */

import { DistributedSystemsTester } from '../services/distributed-systems-tester';
import { PolicyDecisionPoint } from '../services/policy-decision-point';
import { User, Resource } from '../core/types';
import { loadRuntimeConfigFromEnv } from '../core/config-loader';

async function main() {
  // Load runtime configuration from environment variables
  const runtimeConfig = loadRuntimeConfigFromEnv();

  // Validate that region configurations are provided
  if (!runtimeConfig.regionConfigs || runtimeConfig.regionConfigs.length === 0) {
    throw new Error(
      'TEST_REGION_CONFIGS environment variable is required. ' +
      'Set it to a JSON array of region configurations, e.g.: ' +
      '[{"id":"us-east-1","name":"US East","endpoint":"https://api-us-east.example.com",...}]'
    );
  }

  // Initialize Policy Decision Point (optional, can use remote PDPs)
  const pdp = new PolicyDecisionPoint({
    policyEngine: 'custom',
    cacheDecisions: true,
  });

  // Configure distributed system with regions from runtime config
  const tester = new DistributedSystemsTester(
    {
      regions: runtimeConfig.regionConfigs,
      policySync: {
        enabled: true,
        syncInterval: 1000, // 1 second
        consistencyLevel: 'eventual',
      },
    },
    pdp
  );

  // Example user and resource
  const testUser: User = {
    id: 'user-123',
    email: 'researcher@example.com',
    role: 'researcher',
    attributes: {
      department: 'Research',
      clearanceLevel: 'medium',
    },
  };

  const testResource: Resource = {
    id: 'dataset-456',
    type: 'dataset',
    attributes: {
      sensitivity: 'confidential',
      dataClassification: 'internal',
    },
  };

  // Example 1: Test Policy Consistency
  console.log('Testing Policy Consistency Across Regions...');
  const consistencyResult = await tester.testPolicyConsistency({
    name: 'Policy Consistency Test',
    testType: 'policy-consistency',
    user: testUser,
    resource: testResource,
    action: 'read',
  });

  console.log('Policy Consistency Result:', {
    passed: consistencyResult.passed,
    consistent: consistencyResult.consistencyCheck.consistent,
    inconsistencies: consistencyResult.consistencyCheck.inconsistencies,
    regionResults: consistencyResult.regionResults.map(r => ({
      region: r.regionName,
      allowed: r.allowed,
      latency: r.latency,
      error: r.error,
    })),
    performanceMetrics: consistencyResult.performanceMetrics,
  });

  // Example 2: Test Multi-Region Access
  console.log('\nTesting Multi-Region Access...');
  const multiRegionResult = await tester.testMultiRegion({
    name: 'Multi-Region Access Test',
    testType: 'multi-region',
    user: testUser,
    resource: testResource,
    action: 'read',
    expectedResult: true,
    regions: ['us-east-1', 'eu-west-1'], // Test specific regions
  });

  console.log('Multi-Region Result:', {
    passed: multiRegionResult.passed,
    regionResults: multiRegionResult.regionResults.map(r => ({
      region: r.regionName,
      allowed: r.allowed,
      latency: r.latency,
    })),
    consistencyCheck: multiRegionResult.consistencyCheck,
  });

  // Example 3: Test Policy Synchronization
  console.log('\nTesting Policy Synchronization...');
  const syncResult = await tester.testPolicySynchronization({
    name: 'Policy Synchronization Test',
    testType: 'synchronization',
    user: testUser,
    resource: testResource,
    action: 'read',
  });

  console.log('Synchronization Result:', {
    passed: syncResult.passed,
    synchronized: syncResult.synchronizationCheck?.synchronized,
    syncTime: syncResult.synchronizationCheck?.syncTime,
    regionsOutOfSync: syncResult.synchronizationCheck?.regionsOutOfSync,
    regionResults: syncResult.regionResults.map(r => ({
      region: r.regionName,
      allowed: r.allowed,
    })),
  });

  // Example 4: Test Distributed Transaction
  console.log('\nTesting Distributed Transaction (2PC)...');
  const transactionResult = await tester.testDistributedTransaction({
    name: 'Distributed Transaction Test',
    testType: 'transaction',
    user: testUser,
    resource: testResource,
    action: 'write',
  });

  console.log('Transaction Result:', {
    passed: transactionResult.passed,
    regionResults: transactionResult.regionResults.map(r => ({
      region: r.regionName,
      allowed: r.allowed,
      decision: r.decision,
    })),
    performanceMetrics: transactionResult.performanceMetrics,
  });

  // Example 5: Test Eventual Consistency
  console.log('\nTesting Eventual Consistency...');
  const eventualConsistencyResult = await tester.testEventualConsistency({
    name: 'Eventual Consistency Test',
    testType: 'eventual-consistency',
    user: testUser,
    resource: testResource,
    action: 'read',
    timeout: 10000, // Max wait time: 10 seconds
  });

  console.log('Eventual Consistency Result:', {
    passed: eventualConsistencyResult.passed,
    consistent: eventualConsistencyResult.consistencyCheck.consistent,
    convergenceTime: eventualConsistencyResult.details?.convergenceTime,
    performanceMetrics: eventualConsistencyResult.performanceMetrics,
    regionResults: eventualConsistencyResult.regionResults.map(r => ({
      region: r.regionName,
      allowed: r.allowed,
    })),
  });

  // Example 6: Test with different user roles across regions
  console.log('\nTesting Different User Roles Across Regions...');
  const adminUser: User = {
    id: 'admin-1',
    email: 'admin@example.com',
    role: 'admin',
    attributes: {
      department: 'IT',
      clearanceLevel: 'high',
    },
  };

  const viewerUser: User = {
    id: 'viewer-1',
    email: 'viewer@example.com',
    role: 'viewer',
    attributes: {
      department: 'Marketing',
      clearanceLevel: 'low',
    },
  };

  // Test admin access
  const adminResult = await tester.testPolicyConsistency({
    name: 'Admin Access Consistency',
    testType: 'policy-consistency',
    user: adminUser,
    resource: testResource,
    action: 'read',
  });

  // Test viewer access
  const viewerResult = await tester.testPolicyConsistency({
    name: 'Viewer Access Consistency',
    testType: 'policy-consistency',
    user: viewerUser,
    resource: testResource,
    action: 'read',
  });

  console.log('Role-Based Consistency Results:', {
    admin: {
      passed: adminResult.passed,
      consistent: adminResult.consistencyCheck.consistent,
      allowed: adminResult.regionResults.map(r => r.allowed),
    },
    viewer: {
      passed: viewerResult.passed,
      consistent: viewerResult.consistencyCheck.consistent,
      allowed: viewerResult.regionResults.map(r => r.allowed),
    },
  });
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { main as runDistributedSystemsTests };

