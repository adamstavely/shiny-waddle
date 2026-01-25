/**
 * CI/CD Integration Service
 * 
 * Provides integration with CI/CD pipelines for security gates and checks
 */

import { TestResult } from '../core/types';
import { UnifiedFinding } from '../core/unified-finding-schema';

export interface CICDGateConfig {
  enabled: boolean;
  severityThreshold: 'critical' | 'high' | 'medium' | 'low';
  failOnThreshold: boolean;
  maxFindings?: number;
  allowedFindings?: string[]; // Finding IDs that are allowed to pass
}

export interface PreCommitHookResult {
  passed: boolean;
  findings: UnifiedFinding[];
  blockedFiles?: string[];
  message: string;
}

export interface PRSecurityCheckResult {
  passed: boolean;
  findings: UnifiedFinding[];
  newFindings: UnifiedFinding[];
  resolvedFindings: UnifiedFinding[];
  riskScore: number;
  message: string;
  blocking: boolean;
}

export interface BuildSecurityGateResult {
  passed: boolean;
  findings: UnifiedFinding[];
  riskScore: number;
  blocking: boolean;
  message: string;
}

export interface DeploymentSecurityGateResult {
  passed: boolean;
  findings: UnifiedFinding[];
  riskScore: number;
  blocking: boolean;
  message: string;
  deploymentBlocked: boolean;
}

export class CICDIntegration {
  /**
   * Pre-commit hook: Check staged files for security issues
   */
  async runPreCommitHook(
    stagedFiles: string[],
    findings: UnifiedFinding[],
    config: CICDGateConfig
  ): Promise<PreCommitHookResult> {
    // Filter findings for staged files
    const relevantFindings = findings.filter(finding => {
      const filePath = finding.asset?.location?.file;
      if (!filePath) return false;
      return stagedFiles.some(staged => filePath.includes(staged) || staged.includes(filePath));
    });

    // Apply severity threshold
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const thresholdLevel = severityOrder[config.severityThreshold];
    const blockingFindings = relevantFindings.filter(f => {
      if (config.allowedFindings?.includes(f.id)) return false;
      return severityOrder[f.severity] >= thresholdLevel;
    });

    const passed = !config.failOnThreshold || blockingFindings.length === 0;
    const blockedFiles = [...new Set(blockingFindings.map(f => f.asset?.location?.file).filter(Boolean))];

    return {
      passed,
      findings: relevantFindings,
      blockedFiles: blockedFiles as string[],
      message: passed
        ? `✅ Pre-commit check passed (${relevantFindings.length} findings, none blocking)`
        : `❌ Pre-commit check failed: ${blockingFindings.length} blocking findings in ${blockedFiles.length} files`,
    };
  }

  /**
   * PR security check: Compare findings between base and head branches
   */
  async runPRSecurityCheck(
    baseFindings: UnifiedFinding[],
    headFindings: UnifiedFinding[],
    config: CICDGateConfig
  ): Promise<PRSecurityCheckResult> {
    // Find new findings (in head but not in base)
    const baseFindingIds = new Set(baseFindings.map(f => f.id));
    const newFindings = headFindings.filter(f => !baseFindingIds.has(f.id));

    // Find resolved findings (in base but not in head)
    const headFindingIds = new Set(headFindings.map(f => f.id));
    const resolvedFindings = baseFindings.filter(f => !headFindingIds.has(f.id));

    // Calculate risk score for new findings
    const riskScore = this.calculateRiskScore(newFindings);

    // Apply severity threshold
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const thresholdLevel = severityOrder[config.severityThreshold];
    const blockingNewFindings = newFindings.filter(f => {
      if (config.allowedFindings?.includes(f.id)) return false;
      return severityOrder[f.severity] >= thresholdLevel;
    });

    // Check max findings limit
    const exceedsMaxFindings = config.maxFindings !== undefined && newFindings.length > config.maxFindings;

    const blocking = config.failOnThreshold && (blockingNewFindings.length > 0 || exceedsMaxFindings);
    const passed = !blocking;

    return {
      passed,
      findings: headFindings,
      newFindings,
      resolvedFindings,
      riskScore,
      blocking,
      message: passed
        ? `✅ PR security check passed: ${newFindings.length} new findings, ${resolvedFindings.length} resolved`
        : `❌ PR security check failed: ${blockingNewFindings.length} blocking new findings${exceedsMaxFindings ? `, exceeds max findings limit (${config.maxFindings})` : ''}`,
    };
  }

  /**
   * Build-time security gate: Check all findings before build completion
   */
  async runBuildSecurityGate(
    findings: UnifiedFinding[],
    config: CICDGateConfig
  ): Promise<BuildSecurityGateResult> {
    const riskScore = this.calculateRiskScore(findings);

    // Apply severity threshold
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const thresholdLevel = severityOrder[config.severityThreshold];
    const blockingFindings = findings.filter(f => {
      if (config.allowedFindings?.includes(f.id)) return false;
      return severityOrder[f.severity] >= thresholdLevel;
    });

    // Check max findings limit
    const exceedsMaxFindings = config.maxFindings !== undefined && findings.length > config.maxFindings;

    const blocking = config.failOnThreshold && (blockingFindings.length > 0 || exceedsMaxFindings);
    const passed = !blocking;

    return {
      passed,
      findings,
      riskScore,
      blocking,
      message: passed
        ? `✅ Build security gate passed: ${findings.length} findings (risk score: ${riskScore.toFixed(2)})`
        : `❌ Build security gate failed: ${blockingFindings.length} blocking findings${exceedsMaxFindings ? `, exceeds max findings limit (${config.maxFindings})` : ''}`,
    };
  }

  /**
   * Deployment security gate: Final check before deployment
   */
  async runDeploymentSecurityGate(
    findings: UnifiedFinding[],
    environment: string,
    config: CICDGateConfig
  ): Promise<DeploymentSecurityGateResult> {
    const riskScore = this.calculateRiskScore(findings);

    // Stricter thresholds for production
    const isProduction = environment.toLowerCase() === 'production' || environment.toLowerCase() === 'prod';
    const effectiveThreshold = isProduction && config.severityThreshold === 'medium' ? 'high' : config.severityThreshold;

    // Apply severity threshold
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const thresholdLevel = severityOrder[effectiveThreshold];
    const blockingFindings = findings.filter(f => {
      if (config.allowedFindings?.includes(f.id)) return false;
      return severityOrder[f.severity] >= thresholdLevel;
    });

    // Production deployments block on any critical/high findings
    const deploymentBlocked = isProduction && blockingFindings.length > 0;

    const blocking = config.failOnThreshold && (blockingFindings.length > 0 || deploymentBlocked);
    const passed = !blocking;

    return {
      passed,
      findings,
      riskScore,
      blocking,
      deploymentBlocked,
      message: passed
        ? `✅ Deployment security gate passed for ${environment}: ${findings.length} findings (risk score: ${riskScore.toFixed(2)})`
        : `❌ Deployment security gate failed for ${environment}: ${blockingFindings.length} blocking findings${deploymentBlocked ? ' (production deployment blocked)' : ''}`,
    };
  }

  /**
   * Calculate aggregate risk score from findings
   */
  private calculateRiskScore(findings: UnifiedFinding[]): number {
    if (findings.length === 0) return 0;

    const severityWeights = { critical: 10, high: 7, medium: 4, low: 2, info: 1 };
    const totalWeight = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 0), 0);
    const avgWeight = totalWeight / findings.length;

    // Normalize to 0-100 scale
    return Math.min(100, (avgWeight / 10) * 100);
  }

  /**
   * Generate GitHub Actions workflow YAML
   */
  generateGitHubActionsWorkflow(config: CICDGateConfig): string {
    return `name: Security Gates

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  security-gates:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Run security scans
        run: npm run security:scan
        continue-on-error: true

      - name: Check security gates
        run: |
          node heimdall-framework/ci-cd/check-security-gates.js
        env:
          SEVERITY_THRESHOLD: ${config.severityThreshold}
          FAIL_ON_THRESHOLD: ${config.failOnThreshold}
          ${config.maxFindings ? `MAX_FINDINGS: ${config.maxFindings}` : ''}

      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('security-gates-results.json', 'utf8'));
            
            const comment = \`## Security Gate Results
            
            **Status:** \${results.passed ? '✅ Passed' : '❌ Failed'}
            **Findings:** \${results.findings.length}
            **Risk Score:** \${results.riskScore.toFixed(2)}
            
            \${results.message}
            \`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
`;
  }

  /**
   * Generate GitLab CI configuration
   */
  generateGitLabCIConfig(config: CICDGateConfig): string {
    return `stages:
  - security-gates

security-gates:
  stage: security-gates
  image: node:18
  script:
    - npm ci
    - npm run security:scan
    - node heimdall-framework/ci-cd/check-security-gates.js
  variables:
    SEVERITY_THRESHOLD: ${config.severityThreshold}
    FAIL_ON_THRESHOLD: ${config.failOnThreshold}
    ${config.maxFindings ? `MAX_FINDINGS: ${config.maxFindings}` : ''}
  only:
    - merge_requests
    - main
`;
  }

  /**
   * Generate Jenkinsfile
   */
  generateJenkinsfile(config: CICDGateConfig): string {
    return `pipeline {
    agent any
    
    stages {
        stage('Security Gates') {
            steps {
                sh 'npm ci'
                sh 'npm run security:scan'
                sh '''
                    node heimdall-framework/ci-cd/check-security-gates.js
                '''
            }
            environment {
                SEVERITY_THRESHOLD = '${config.severityThreshold}'
                FAIL_ON_THRESHOLD = '${config.failOnThreshold}'
                ${config.maxFindings ? `MAX_FINDINGS = '${config.maxFindings}'` : ''}
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'security-gates-results.json'
        }
        failure {
            emailext subject: 'Security Gate Failed',
                     body: 'Security gate check failed. Please review findings.',
                     to: '${process.env.EMAIL_RECIPIENTS || ''}'
        }
    }
}
`;
  }
}

