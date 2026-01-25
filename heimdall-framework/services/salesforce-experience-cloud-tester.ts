/**
 * Salesforce Experience Cloud Testing Service
 * 
 * Wraps Google's aura-inspector tool to test Salesforce Experience Cloud applications
 * for security misconfigurations and vulnerabilities.
 * 
 * Reference: https://github.com/google/aura-inspector
 */

import { TestResult } from '../core/types';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

const execAsync = promisify(exec);

export interface SalesforceExperienceCloudConfig {
  /** Root URL of Salesforce application to audit */
  url: string;
  
  /** Cookies after authenticating to Salesforce application */
  cookies?: string;
  
  /** Output directory for aura-inspector results */
  outputDir?: string;
  
  /** Pull records only for the provided objects (comma separated) */
  objectList?: string[];
  
  /** Target Salesforce app's path (e.g., /myApp) */
  app?: string;
  
  /** Target Salesforce aura's path (e.g., /aura) */
  aura?: string;
  
  /** Context to be used as aura.context in POST requests */
  context?: string;
  
  /** Aura token to be used as aura.token in POST requests */
  token?: string;
  
  /** Do not check for GraphQL capability and do not use it */
  noGraphQL?: boolean;
  
  /** Proxy requests */
  proxy?: string;
  
  /** Ignore invalid TLS certificates */
  insecure?: boolean;
  
  /** Provide a request file to an /aura endpoint */
  auraRequestFile?: string;
  
  /** Path to aura-inspector installation (default: looks for aura_cli.py in PATH) */
  auraInspectorPath?: string;
  
  /** Timeout for aura-inspector execution (default: 5 minutes) */
  timeout?: number;
  
  /** Python executable path (default: 'python3') */
  pythonPath?: string;
}

export interface AuraInspectorFinding {
  type: 'guest_access' | 'authenticated_access' | 'graphql' | 'self_registration' | 'record_list' | 'home_url' | 'object_access';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  details: any;
  objects?: string[];
  urls?: string[];
  recordCount?: number;
  accessibleRecords?: any[];
}

export interface SalesforceExperienceCloudTestResult extends TestResult {
  // Additional properties stored in details
  // finding, accessibleRecords, recordCount, urls, objects are in details
}

export class SalesforceExperienceCloudTester {
  private config: SalesforceExperienceCloudConfig;
  private outputDir: string;

  constructor(config: SalesforceExperienceCloudConfig) {
    this.config = config;
    this.outputDir = config.outputDir || path.join(os.tmpdir(), 'aura-inspector-output');
  }

  /**
   * Test accessible records from Guest context
   */
  async testGuestAccess(): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'Guest Access Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const findings = await this.runAuraInspector({
        ...this.config,
        cookies: undefined, // Force guest context
      });

      const guestFindings = findings.filter(f => f.type === 'guest_access');
      const hasCriticalIssues = guestFindings.some(f => f.severity === 'critical' || f.severity === 'high');

      result.passed = !hasCriticalIssues;
      const accessibleRecords = guestFindings.flatMap(f => f.accessibleRecords || []);
      const recordCount = guestFindings.reduce((sum, f) => sum + (f.recordCount || 0), 0);
      result.details = {
        findings: guestFindings,
        accessibleRecords,
        recordCount,
        summary: {
          totalFindings: guestFindings.length,
          criticalCount: guestFindings.filter(f => f.severity === 'critical').length,
          highCount: guestFindings.filter(f => f.severity === 'high').length,
          mediumCount: guestFindings.filter(f => f.severity === 'medium').length,
        },
      };

      if (hasCriticalIssues) {
        result.error = `Found ${guestFindings.length} guest access issues`;
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Test accessible records from Authenticated context
   */
  async testAuthenticatedAccess(): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'Authenticated Access Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    if (!this.config.cookies && !this.config.auraRequestFile) {
      result.passed = false;
      result.error = 'Authenticated access test requires cookies or auraRequestFile';
      return result;
    }

    try {
      const findings = await this.runAuraInspector(this.config);

      const authFindings = findings.filter(f => f.type === 'authenticated_access');
      const hasCriticalIssues = authFindings.some(f => f.severity === 'critical' || f.severity === 'high');

      result.passed = !hasCriticalIssues;
      const accessibleRecords = authFindings.flatMap(f => f.accessibleRecords || []);
      const recordCount = authFindings.reduce((sum, f) => sum + (f.recordCount || 0), 0);
      result.details = {
        findings: authFindings,
        accessibleRecords,
        recordCount,
        summary: {
          totalFindings: authFindings.length,
          criticalCount: authFindings.filter(f => f.severity === 'critical').length,
          highCount: authFindings.filter(f => f.severity === 'high').length,
          mediumCount: authFindings.filter(f => f.severity === 'medium').length,
        },
      };

      if (hasCriticalIssues) {
        result.error = `Found ${authFindings.length} authenticated access issues`;
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Test GraphQL capability
   */
  async testGraphQLCapability(): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'GraphQL Capability Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    if (this.config.noGraphQL) {
      result.passed = true;
      result.details = { message: 'GraphQL testing disabled' };
      return result;
    }

    try {
      const findings = await this.runAuraInspector({
        ...this.config,
        noGraphQL: false,
      });

      const graphqlFindings = findings.filter(f => f.type === 'graphql');
      const hasVulnerabilities = graphqlFindings.some(f => f.severity === 'critical' || f.severity === 'high');

      result.passed = !hasVulnerabilities;
      result.details = {
        findings: graphqlFindings,
        graphqlAvailable: graphqlFindings.length > 0,
      };

      if (hasVulnerabilities) {
        result.error = 'GraphQL capability exposes security vulnerabilities';
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Test self-registration capabilities
   */
  async testSelfRegistration(): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'Self-Registration Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const findings = await this.runAuraInspector(this.config);

      const registrationFindings = findings.filter(f => f.type === 'self_registration');
      const hasRegistration = registrationFindings.length > 0;

      // Self-registration is typically a security concern if not properly configured
      result.passed = !hasRegistration || registrationFindings.every(f => f.severity === 'low' || f.severity === 'info');
      result.details = {
        findings: registrationFindings,
        selfRegistrationAvailable: hasRegistration,
      };

      if (hasRegistration && registrationFindings.some(f => f.severity !== 'low' && f.severity !== 'info')) {
        result.error = 'Self-registration capability detected with security concerns';
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Test Record List components
   */
  async testRecordListComponents(): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'Record List Components Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const findings = await this.runAuraInspector(this.config);

      const recordListFindings = findings.filter(f => f.type === 'record_list');
      const hasMisconfigurations = recordListFindings.some(f => f.severity === 'critical' || f.severity === 'high');

      result.passed = !hasMisconfigurations;
      const objects = recordListFindings.flatMap(f => f.objects || []);
      result.details = {
        findings: recordListFindings,
        objects,
        summary: {
          totalFindings: recordListFindings.length,
          misconfiguredObjects: recordListFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length,
        },
      };

      if (hasMisconfigurations) {
        result.error = `Found ${recordListFindings.length} misconfigured record list components`;
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Test Home URLs for unauthorized admin access
   */
  async testHomeURLs(): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'Home URLs Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const findings = await this.runAuraInspector(this.config);

      const homeURLFindings = findings.filter(f => f.type === 'home_url');
      const hasUnauthorizedAccess = homeURLFindings.some(f => f.severity === 'critical' || f.severity === 'high');

      result.passed = !hasUnauthorizedAccess;
      const urls = homeURLFindings.flatMap(f => f.urls || []);
      result.details = {
        findings: homeURLFindings,
        urls,
        summary: {
          totalFindings: homeURLFindings.length,
          unauthorizedURLs: homeURLFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length,
        },
      };

      if (hasUnauthorizedAccess) {
        result.error = `Found ${homeURLFindings.length} unauthorized home URLs`;
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Test access to specific objects
   */
  async testObjectAccess(objects: string[]): Promise<SalesforceExperienceCloudTestResult> {
    const result: SalesforceExperienceCloudTestResult = {
      testType: 'salesforce-experience-cloud',
      testName: 'Object Access Test',
      passed: false,
      timestamp: new Date(),
      details: {},
    };

    try {
      const findings = await this.runAuraInspector({
        ...this.config,
        objectList: objects,
      });

      const objectFindings = findings.filter(f => f.type === 'object_access');
      const hasUnauthorizedAccess = objectFindings.some(f => f.severity === 'critical' || f.severity === 'high');

      result.passed = !hasUnauthorizedAccess;
      result.details = {
        findings: objectFindings,
        testedObjects: objects,
        summary: {
          totalFindings: objectFindings.length,
          unauthorizedAccess: objectFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length,
        },
      };

      if (hasUnauthorizedAccess) {
        result.error = `Found unauthorized access to ${objectFindings.length} objects`;
      }
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message, stack: error.stack };
    }

    return result;
  }

  /**
   * Run full aura-inspector audit
   */
  async runFullAudit(): Promise<SalesforceExperienceCloudTestResult[]> {
    const results: SalesforceExperienceCloudTestResult[] = [];

    try {
      const findings = await this.runAuraInspector(this.config);

      // Group findings by type and create test results
      const findingsByType = new Map<string, AuraInspectorFinding[]>();
      findings.forEach(finding => {
        if (!findingsByType.has(finding.type)) {
          findingsByType.set(finding.type, []);
        }
        findingsByType.get(finding.type)!.push(finding);
      });

      // Create test result for each finding type
      findingsByType.forEach((typeFindings, type) => {
        const hasCriticalIssues = typeFindings.some(f => f.severity === 'critical' || f.severity === 'high');

        const result: SalesforceExperienceCloudTestResult = {
          testType: 'salesforce-experience-cloud',
          testName: `${this.formatFindingType(type)} - Full Audit`,
          passed: !hasCriticalIssues,
          timestamp: new Date(),
          details: {
            findings: typeFindings,
            summary: {
              totalFindings: typeFindings.length,
              criticalCount: typeFindings.filter(f => f.severity === 'critical').length,
              highCount: typeFindings.filter(f => f.severity === 'high').length,
              mediumCount: typeFindings.filter(f => f.severity === 'medium').length,
            },
          },
        };

        if (hasCriticalIssues) {
          result.error = `Found ${typeFindings.length} ${type} issues`;
        }

        results.push(result);
      });
    } catch (error: any) {
      // Return error result
      results.push({
        testType: 'salesforce-experience-cloud',
        testName: 'Full Audit - Error',
        passed: false,
        timestamp: new Date(),
        error: error.message,
        details: { error: error.message, stack: error.stack },
      });
    }

    return results;
  }

  /**
   * Run aura-inspector CLI and parse results
   */
  private async runAuraInspector(config: SalesforceExperienceCloudConfig): Promise<AuraInspectorFinding[]> {
    // Ensure output directory exists
    await fs.mkdir(this.outputDir, { recursive: true });

    // Build CLI arguments
    const args = this.buildCLIArgs(config);
    
    // Determine Python and aura-inspector paths
    const pythonPath = config.pythonPath || 'python3';
    const auraInspectorPath = config.auraInspectorPath || 'aura_cli.py';
    
    // Build command
    const command = `${pythonPath} ${auraInspectorPath} ${args.join(' ')}`;

    try {
      // Execute aura-inspector
      const { stdout, stderr } = await execAsync(command, {
        cwd: this.outputDir,
        timeout: config.timeout || 300000, // 5 minutes default
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });

      // Parse output - aura-inspector outputs JSON to stdout or file
      const outputFile = path.join(this.outputDir, 'results.json');
      let findings: AuraInspectorFinding[] = [];

      try {
        const outputData = await fs.readFile(outputFile, 'utf-8');
        const parsed = JSON.parse(outputData);
        findings = this.parseAuraInspectorOutput(parsed);
      } catch (fileError) {
        // Try to parse stdout if file doesn't exist
        if (stdout) {
          try {
            const parsed = JSON.parse(stdout);
            findings = this.parseAuraInspectorOutput(parsed);
          } catch (parseError) {
            // If JSON parsing fails, try to extract findings from text output
            findings = this.parseTextOutput(stdout, stderr);
          }
        }
      }

      return findings;
    } catch (error: any) {
      // Handle execution errors
      if (error.code === 'ENOENT') {
        throw new Error(`aura-inspector not found. Please install it: pipx install git+https://github.com/google/aura-inspector`);
      }
      if (error.code === 'ETIMEDOUT' || error.signal === 'SIGTERM') {
        throw new Error(`aura-inspector execution timed out after ${config.timeout || 300000}ms`);
      }
      throw new Error(`Failed to execute aura-inspector: ${error.message}`);
    }
  }

  /**
   * Build CLI arguments for aura-inspector
   */
  private buildCLIArgs(config: SalesforceExperienceCloudConfig): string[] {
    const args: string[] = [];

    // Required: URL
    args.push('-u', config.url);

    // Optional: Cookies
    if (config.cookies) {
      args.push('-c', config.cookies);
    }

    // Optional: Output directory
    if (this.outputDir) {
      args.push('-o', this.outputDir);
    }

    // Optional: Object list
    if (config.objectList && config.objectList.length > 0) {
      args.push('-l', config.objectList.join(','));
    }

    // Optional: App path
    if (config.app) {
      args.push('--app', config.app);
    }

    // Optional: Aura path
    if (config.aura) {
      args.push('--aura', config.aura);
    }

    // Optional: Context
    if (config.context) {
      args.push('--context', config.context);
    }

    // Optional: Token
    if (config.token) {
      args.push('--token', config.token);
    }

    // Optional: No GraphQL
    if (config.noGraphQL) {
      args.push('--no-gql');
    }

    // Optional: Proxy
    if (config.proxy) {
      args.push('-p', config.proxy);
    }

    // Optional: Insecure (ignore TLS)
    if (config.insecure) {
      args.push('-k');
    }

    // Optional: Aura request file
    if (config.auraRequestFile) {
      args.push('-r', config.auraRequestFile);
    }

    // Add verbose flag for better output
    args.push('-v');

    return args;
  }

  /**
   * Parse aura-inspector JSON output
   */
  private parseAuraInspectorOutput(output: any): AuraInspectorFinding[] {
    const findings: AuraInspectorFinding[] = [];

    // Parse based on aura-inspector output structure
    // This is a placeholder - actual structure depends on aura-inspector output format
    if (Array.isArray(output)) {
      output.forEach((item: any) => {
        findings.push(this.parseFinding(item));
      });
    } else if (output.findings) {
      output.findings.forEach((item: any) => {
        findings.push(this.parseFinding(item));
      });
    } else if (output.results) {
      output.results.forEach((item: any) => {
        findings.push(this.parseFinding(item));
      });
    }

    return findings;
  }

  /**
   * Parse a single finding from aura-inspector output
   */
  private parseFinding(item: any): AuraInspectorFinding {
    // Map aura-inspector output to our finding format
    // This is a placeholder - adjust based on actual aura-inspector output
    return {
      type: item.type || 'object_access',
      severity: this.mapSeverity(item.severity || item.level || 'medium'),
      description: item.description || item.message || item.summary || 'Security finding',
      details: item.details || item,
      objects: item.objects || item.object_list || [],
      urls: item.urls || item.url_list || [],
      recordCount: item.record_count || item.count || 0,
      accessibleRecords: item.records || item.accessible_records || [],
    };
  }

  /**
   * Map severity levels
   */
  private mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const lower = severity.toLowerCase();
    if (lower.includes('critical') || lower.includes('critical')) return 'critical';
    if (lower.includes('high') || lower.includes('high')) return 'high';
    if (lower.includes('medium') || lower.includes('medium')) return 'medium';
    if (lower.includes('low') || lower.includes('low')) return 'low';
    return 'info';
  }

  /**
   * Parse text output (fallback if JSON parsing fails)
   */
  private parseTextOutput(stdout: string, stderr: string): AuraInspectorFinding[] {
    const findings: AuraInspectorFinding[] = [];
    
    // Try to extract findings from text output
    // This is a basic implementation - may need refinement based on actual output
    const lines = (stdout + '\n' + stderr).split('\n');
    
    for (const line of lines) {
      if (line.includes('accessible') || line.includes('vulnerability') || line.includes('misconfiguration')) {
        findings.push({
          type: 'object_access',
          severity: 'medium',
          description: line.trim(),
          details: { rawOutput: line },
        });
      }
    }

    return findings;
  }

  /**
   * Format finding type for display
   */
  private formatFindingType(type: string): string {
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }
}
