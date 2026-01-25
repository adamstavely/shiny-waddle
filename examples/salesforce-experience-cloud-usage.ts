/**
 * Salesforce Experience Cloud Testing Example
 * 
 * Demonstrates how to use the Salesforce Experience Cloud tester
 * to audit Salesforce Experience Cloud applications for security issues.
 */

import {
  SalesforceExperienceCloudTester,
  SalesforceExperienceCloudConfig,
} from '../heimdall-framework/services/salesforce-experience-cloud-tester';

async function main() {
  // Configure the tester
  const config: SalesforceExperienceCloudConfig = {
    url: 'https://example.force.com',
    // Optional: Provide cookies for authenticated context
    // cookies: 'sid=...;',
    // Optional: Specify custom app path
    // app: '/myApp',
    // Optional: Specify custom aura path
    // aura: '/aura',
    // Optional: Test specific objects
    // objectList: ['Account', 'Contact', 'Opportunity'],
    // Optional: Set timeout (default: 5 minutes)
    timeout: 300000,
    // Optional: Python path (default: 'python3')
    // pythonPath: 'python3',
    // Optional: Path to aura-inspector (default: looks in PATH)
    // auraInspectorPath: '/path/to/aura_cli.py',
  };

  const tester = new SalesforceExperienceCloudTester(config);

  console.log('Starting Salesforce Experience Cloud security audit...\n');

  try {
    // Test 1: Guest Access
    console.log('1. Testing Guest Access...');
    const guestResult = await tester.testGuestAccess();
    console.log(`   Status: ${guestResult.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`   Findings: ${guestResult.details?.summary?.totalFindings || 0}`);
    if (guestResult.details?.summary) {
      console.log(`   Critical: ${guestResult.details.summary.criticalCount || 0}`);
      console.log(`   High: ${guestResult.details.summary.highCount || 0}`);
    }
    console.log('');

    // Test 2: Authenticated Access (if cookies provided)
    if (config.cookies) {
      console.log('2. Testing Authenticated Access...');
      const authResult = await tester.testAuthenticatedAccess();
      console.log(`   Status: ${authResult.passed ? 'PASSED' : 'FAILED'}`);
      console.log(`   Findings: ${authResult.details?.summary?.totalFindings || 0}`);
      if (authResult.details?.summary) {
        console.log(`   Critical: ${authResult.details.summary.criticalCount || 0}`);
        console.log(`   High: ${authResult.details.summary.highCount || 0}`);
      }
      console.log('');
    }

    // Test 3: GraphQL Capability
    console.log('3. Testing GraphQL Capability...');
    const graphqlResult = await tester.testGraphQLCapability();
    console.log(`   Status: ${graphqlResult.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`   GraphQL Available: ${graphqlResult.details?.graphqlAvailable || false}`);
    console.log('');

    // Test 4: Self-Registration
    console.log('4. Testing Self-Registration...');
    const registrationResult = await tester.testSelfRegistration();
    console.log(`   Status: ${registrationResult.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`   Self-Registration Available: ${registrationResult.details?.selfRegistrationAvailable || false}`);
    console.log('');

    // Test 5: Record List Components
    console.log('5. Testing Record List Components...');
    const recordListResult = await tester.testRecordListComponents();
    console.log(`   Status: ${recordListResult.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`   Findings: ${recordListResult.details?.summary?.totalFindings || 0}`);
    if (recordListResult.details?.objects) {
      console.log(`   Objects: ${recordListResult.details.objects.join(', ')}`);
    }
    console.log('');

    // Test 6: Home URLs
    console.log('6. Testing Home URLs...');
    const homeURLResult = await tester.testHomeURLs();
    console.log(`   Status: ${homeURLResult.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`   Findings: ${homeURLResult.details?.summary?.totalFindings || 0}`);
    if (homeURLResult.details?.urls) {
      console.log(`   URLs Found: ${homeURLResult.details.urls.length}`);
    }
    console.log('');

    // Test 7: Object Access (if objectList provided)
    if (config.objectList && config.objectList.length > 0) {
      console.log('7. Testing Object Access...');
      const objectResult = await tester.testObjectAccess(config.objectList);
      console.log(`   Status: ${objectResult.passed ? 'PASSED' : 'FAILED'}`);
      console.log(`   Findings: ${objectResult.details?.summary?.totalFindings || 0}`);
      console.log('');
    }

    // Test 8: Full Audit
    console.log('8. Running Full Audit...');
    const auditResults = await tester.runFullAudit();
    console.log(`   Total Test Results: ${auditResults.length}`);
    const failedTests = auditResults.filter(r => !r.passed);
    console.log(`   Failed Tests: ${failedTests.length}`);
    console.log('');

    // Summary
    console.log('=== Audit Summary ===');
    const allResults = [
      guestResult,
      ...(config.cookies ? [authResult] : []),
      graphqlResult,
      registrationResult,
      recordListResult,
      homeURLResult,
      ...(config.objectList ? [objectResult] : []),
      ...auditResults,
    ];
    const totalTests = allResults.length;
    const passedTests = allResults.filter(r => r.passed).length;
    const failedTestsCount = totalTests - passedTests;

    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests}`);
    console.log(`Failed: ${failedTestsCount}`);
    console.log(`Pass Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);

  } catch (error: any) {
    console.error('Error during audit:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run the example
if (require.main === module) {
  main().catch(console.error);
}

export { main as runSalesforceExperienceCloudExample };
