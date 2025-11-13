/**
 * Infrastructure-as-Code Scanner Service
 * 
 * Scans Terraform, CloudFormation, and other IaC files for security issues
 */

import { IACScanResult } from '../core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export class IACScanner {
  /**
   * Scan Terraform files
   */
  async scanTerraform(files: string[]): Promise<IACScanResult> {
    const findings: IACScanResult['findings'] = [];

    for (const file of files) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');

        // Check for common security issues
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const lineNum = i + 1;

          // Check for hardcoded secrets
          if (this.detectHardcodedSecret(line)) {
            findings.push({
              file,
              line: lineNum,
              severity: 'critical',
              type: 'hardcoded-secret',
              description: 'Potential hardcoded secret detected',
              recommendation: 'Use environment variables or secret management',
            });
          }

          // Check for overly permissive access
          if (this.detectOverlyPermissive(line)) {
            findings.push({
              file,
              line: lineNum,
              severity: 'high',
              type: 'overly-permissive',
              description: 'Overly permissive access configuration',
              recommendation: 'Apply principle of least privilege',
            });
          }

          // Check for missing policies
          if (this.detectMissingPolicy(line)) {
            findings.push({
              file,
              line: lineNum,
              severity: 'medium',
              type: 'missing-policy',
              description: 'Missing access control policy',
              recommendation: 'Add explicit access control policies',
            });
          }
        }
      } catch (error: any) {
        findings.push({
          file,
          line: 0,
          severity: 'low',
          type: 'insecure-config',
          description: `Error reading file: ${error.message}`,
          recommendation: 'Fix file access issues',
        });
      }
    }

    return {
      files,
      findings,
      passed: findings.filter(f => f.severity === 'critical' || f.severity === 'high').length === 0,
    };
  }

  /**
   * Scan CloudFormation templates
   */
  async scanCloudFormation(templates: string[]): Promise<IACScanResult> {
    // Similar to Terraform scanning
    return this.scanTerraform(templates);
  }

  /**
   * Scan files (auto-detect type)
   */
  async scanFiles(files: string[]): Promise<IACScanResult> {
    const terraformFiles = files.filter(f => f.endsWith('.tf') || f.endsWith('.tfvars'));
    const cloudFormationFiles = files.filter(f => 
      f.includes('cloudformation') || f.endsWith('.cfn') || f.endsWith('.template')
    );

    const results: IACScanResult[] = [];

    if (terraformFiles.length > 0) {
      results.push(await this.scanTerraform(terraformFiles));
    }

    if (cloudFormationFiles.length > 0) {
      results.push(await this.scanCloudFormation(cloudFormationFiles));
    }

    // Combine results
    const allFiles = [...new Set(results.flatMap(r => r.files))];
    const allFindings = results.flatMap(r => r.findings);
    const allPassed = results.every(r => r.passed);

    return {
      files: allFiles,
      findings: allFindings,
      passed: allPassed,
    };
  }

  /**
   * Validate access control in IaC config
   */
  async validateAccessControl(iacConfig: any): Promise<any[]> {
    const issues: any[] = [];

    // Check for missing access controls
    if (!iacConfig.access_control) {
      issues.push({
        severity: 'high',
        type: 'missing-policy',
        description: 'Missing access control configuration',
      });
    }

    return issues;
  }

  /**
   * Detect hardcoded secrets
   */
  private detectHardcodedSecret(line: string): boolean {
    const patterns = [
      /password\s*=\s*["'][^"']+["']/i,
      /secret\s*=\s*["'][^"']+["']/i,
      /api[_-]?key\s*=\s*["'][^"']+["']/i,
      /token\s*=\s*["'][^"']+["']/i,
    ];

    return patterns.some(pattern => pattern.test(line));
  }

  /**
   * Detect overly permissive access
   */
  private detectOverlyPermissive(line: string): boolean {
    const patterns = [
      /action\s*=\s*["']\*["']/i,
      /principal\s*=\s*["']\*["']/i,
      /effect\s*=\s*["']allow["'].*resource\s*=\s*["']\*["']/i,
    ];

    return patterns.some(pattern => pattern.test(line));
  }

  /**
   * Detect missing policy
   */
  private detectMissingPolicy(line: string): boolean {
    // Check for resource definitions without policies
    const resourcePattern = /resource\s+["'][^"']+["']/i;
    const policyPattern = /policy|access[_-]?control|permission/i;

    return resourcePattern.test(line) && !policyPattern.test(line);
  }
}


