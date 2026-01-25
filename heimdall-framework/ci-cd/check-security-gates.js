#!/usr/bin/env node

/**
 * Security Gates Check Script
 * 
 * Checks security findings against configured gates and exits with appropriate code
 */

const fs = require('fs');
const path = require('path');

const reportPath = path.join(__dirname, '../reports/security-gates-results.json');
const findingsPath = path.join(__dirname, '../reports/unified-findings.json');

// Get configuration from environment
const severityThreshold = process.env.SEVERITY_THRESHOLD || 'high';
const failOnThreshold = process.env.FAIL_ON_THRESHOLD !== 'false';
const maxFindings = process.env.MAX_FINDINGS ? parseInt(process.env.MAX_FINDINGS) : undefined;

const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const thresholdLevel = severityOrder[severityThreshold] || 3;

// Load findings
let findings = [];
if (fs.existsSync(findingsPath)) {
  try {
    const findingsData = fs.readFileSync(findingsPath, 'utf-8');
    findings = JSON.parse(findingsData);
  } catch (error) {
    console.error('Error loading findings:', error.message);
    process.exit(1);
  }
}

// Filter blocking findings
const blockingFindings = findings.filter(f => {
  const findingSeverity = severityOrder[f.severity] || 0;
  return findingSeverity >= thresholdLevel;
});

// Check max findings limit
const exceedsMaxFindings = maxFindings !== undefined && findings.length > maxFindings;

// Calculate risk score
const severityWeights = { critical: 10, high: 7, medium: 4, low: 2, info: 1 };
const totalWeight = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 0), 0);
const riskScore = findings.length > 0 ? Math.min(100, (totalWeight / findings.length / 10) * 100) : 0;

// Determine if gate passed
const passed = !failOnThreshold || (blockingFindings.length === 0 && !exceedsMaxFindings);

// Create results
const results = {
  passed,
  findings: findings.length,
  blockingFindings: blockingFindings.length,
  riskScore: riskScore.toFixed(2),
  message: passed
    ? `✅ Security gate passed: ${findings.length} findings (risk score: ${riskScore.toFixed(2)})`
    : `❌ Security gate failed: ${blockingFindings.length} blocking findings${exceedsMaxFindings ? `, exceeds max findings limit (${maxFindings})` : ''}`,
  timestamp: new Date().toISOString(),
  config: {
    severityThreshold,
    failOnThreshold,
    maxFindings,
  },
};

// Save results
const resultsDir = path.dirname(reportPath);
if (!fs.existsSync(resultsDir)) {
  fs.mkdirSync(resultsDir, { recursive: true });
}
fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));

// Output results
console.log(results.message);
console.log(`\nFindings Summary:`);
console.log(`  Total: ${findings.length}`);
console.log(`  Blocking: ${blockingFindings.length}`);
console.log(`  Risk Score: ${riskScore.toFixed(2)}`);

if (blockingFindings.length > 0) {
  console.log(`\nBlocking Findings:`);
  blockingFindings.slice(0, 10).forEach(f => {
    console.log(`  - [${f.severity.toUpperCase()}] ${f.title} (${f.id})`);
  });
  if (blockingFindings.length > 10) {
    console.log(`  ... and ${blockingFindings.length - 10} more`);
  }
}

// Exit with appropriate code
process.exit(passed ? 0 : 1);
