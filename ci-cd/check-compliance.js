#!/usr/bin/env node

/**
 * CI/CD Compliance Check Script
 * 
 * Exits with non-zero code if compliance tests fail, blocking merges
 */

const fs = require('fs');
const path = require('path');

const reportPath = path.join(__dirname, '../reports/compliance-report.json');

if (!fs.existsSync(reportPath)) {
  console.error('Compliance report not found. Tests may have failed to run.');
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

const minComplianceScore = process.env.MIN_COMPLIANCE_SCORE || 100;
const actualScore = report.summary?.passRate || 0;

console.log(`Compliance Score: ${actualScore}%`);
console.log(`Minimum Required: ${minComplianceScore}%`);

if (actualScore < minComplianceScore) {
  console.error(`❌ Compliance score ${actualScore}% is below minimum ${minComplianceScore}%`);
  console.error('Blocking merge due to compliance violations.');
  
  if (report.summary?.failedTests > 0) {
    console.error(`\nFailed Tests: ${report.summary.failedTests}`);
    const failures = report.results.filter(r => !r.passed);
    failures.forEach(failure => {
      console.error(`  - ${failure.testName}: ${failure.error || 'Test failed'}`);
    });
  }
  
  process.exit(1);
}

if (report.summary?.failedTests > 0) {
  console.warn(`⚠️  ${report.summary.failedTests} tests failed, but score is above minimum`);
  console.warn('Review failed tests before merging.');
}

console.log('✅ Compliance check passed');
process.exit(0);

