#!/usr/bin/env node

/**
 * Pre-commit Hook
 * 
 * Checks staged files for security issues before commit
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Get staged files
let stagedFiles = [];
try {
  const output = execSync('git diff --cached --name-only', { encoding: 'utf-8' });
  stagedFiles = output.trim().split('\n').filter(Boolean);
} catch (error) {
  console.error('Error getting staged files:', error.message);
  process.exit(1);
}

if (stagedFiles.length === 0) {
  console.log('No files staged for commit');
  process.exit(0);
}

console.log(`Checking ${stagedFiles.length} staged files for security issues...`);

// Run security scan on staged files
const findingsPath = path.join(__dirname, '../reports/unified-findings.json');
let findings = [];

if (fs.existsSync(findingsPath)) {
  try {
    const findingsData = fs.readFileSync(findingsPath, 'utf-8');
    findings = JSON.parse(findingsData);
  } catch (error) {
    console.warn('Warning: Could not load findings file');
  }
}

// Filter findings for staged files
const relevantFindings = findings.filter(finding => {
  const filePath = finding.asset?.location?.file;
  if (!filePath) return false;
  return stagedFiles.some(staged => filePath.includes(staged) || staged.includes(filePath));
});

// Check for blocking findings (critical/high severity)
const blockingFindings = relevantFindings.filter(f => {
  return f.severity === 'critical' || f.severity === 'high';
});

if (blockingFindings.length > 0) {
  console.error('\n❌ Pre-commit check failed: Blocking security findings detected');
  console.error(`\nFound ${blockingFindings.length} blocking findings in staged files:\n`);
  
  blockingFindings.forEach(f => {
    const file = f.asset?.location?.file || 'unknown';
    console.error(`  [${f.severity.toUpperCase()}] ${file}: ${f.title}`);
  });
  
  console.error('\nPlease fix these issues before committing.');
  console.error('To bypass this check (not recommended), use: git commit --no-verify');
  process.exit(1);
}

console.log(`✅ Pre-commit check passed: ${relevantFindings.length} findings, none blocking`);
process.exit(0);

