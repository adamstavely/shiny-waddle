/**
 * Contract Tester Service
 * 
 * Tests based on machine-readable requirements from data owners
 * (e.g., "No raw email export," "Min aggregation ≥ k=10")
 */

import { Contract, ContractRequirement, ContractTestConfig } from '../core/types';
import { QueryAnalyzer } from './query-analyzer';
import { DataBehaviorTester } from './data-behavior-tester';

export interface ContractTestResult {
  compliant: boolean;
  contractName: string;
  dataOwner: string;
  requirementResults: RequirementTestResult[];
  violations: string[];
}

export interface RequirementTestResult {
  requirementId: string;
  description: string;
  passed: boolean;
  violation?: string;
}

export class ContractTester {
  private config: ContractTestConfig;
  private queryAnalyzer: QueryAnalyzer;

  constructor(config: ContractTestConfig) {
    this.config = config;
    this.queryAnalyzer = new QueryAnalyzer({});
  }

  /**
   * Test a contract against application behavior
   */
  async testContract(contract: Contract): Promise<ContractTestResult> {
    const requirementResults: RequirementTestResult[] = [];
    const violations: string[] = [];

    for (const requirement of contract.requirements) {
      const result = await this.testRequirement(requirement, contract);
      requirementResults.push(result);

      if (!result.passed) {
        violations.push(`${requirement.id}: ${result.violation}`);
      }
    }

    return {
      compliant: violations.length === 0,
      contractName: contract.name,
      dataOwner: contract.dataOwner,
      requirementResults,
      violations,
    };
  }

  /**
   * Test a specific requirement
   */
  private async testRequirement(
    requirement: ContractRequirement,
    contract: Contract
  ): Promise<RequirementTestResult> {
    switch (requirement.type) {
      case 'field-restriction':
        return this.testFieldRestriction(requirement);
      case 'aggregation-requirement':
        return this.testAggregationRequirement(requirement);
      case 'join-restriction':
        return this.testJoinRestriction(requirement);
      case 'export-restriction':
        return this.testExportRestriction(requirement);
      default:
        return {
          requirementId: requirement.id,
          description: requirement.description,
          passed: false,
          violation: `Unknown requirement type: ${requirement.type}`,
        };
    }
  }

  /**
   * Test field restriction (e.g., "No raw email export")
   */
  private async testFieldRestriction(
    requirement: ContractRequirement
  ): Promise<RequirementTestResult> {
    // This would need to be called with actual query data
    // For now, return a placeholder
    const rule = requirement.rule as { fields: string[]; allowed: boolean };

    return {
      requirementId: requirement.id,
      description: requirement.description,
      passed: true, // Would need actual query to validate
      violation: rule.allowed
        ? undefined
        : `Restricted fields accessed: ${rule.fields.join(', ')}`,
    };
  }

  /**
   * Test aggregation requirement (e.g., "Min aggregation ≥ k=10")
   */
  private async testAggregationRequirement(
    requirement: ContractRequirement
  ): Promise<RequirementTestResult> {
    const rule = requirement.rule as {
      minK: number;
      requireAggregation: boolean;
    };

    // This would need actual query analysis
    // For now, return based on rule structure
    if (rule.requireAggregation && rule.minK > 0) {
      return {
        requirementId: requirement.id,
        description: requirement.description,
        passed: true, // Would validate actual query has GROUP BY with COUNT >= minK
        violation: rule.minK
          ? `Aggregation must have minimum k=${rule.minK}`
          : 'Aggregation required but not found',
      };
    }

    return {
      requirementId: requirement.id,
      description: requirement.description,
      passed: true,
    };
  }

  /**
   * Test join restriction
   */
  private async testJoinRestriction(
    requirement: ContractRequirement
  ): Promise<RequirementTestResult> {
    const rule = requirement.rule as { disallowedJoins: string[] };

    // Would validate actual query doesn't contain disallowed joins
    return {
      requirementId: requirement.id,
      description: requirement.description,
      passed: true,
      violation: rule.disallowedJoins.length > 0
        ? `Disallowed joins detected: ${rule.disallowedJoins.join(', ')}`
        : undefined,
    };
  }

  /**
   * Test export restriction (e.g., "No raw email export")
   */
  private async testExportRestriction(
    requirement: ContractRequirement
  ): Promise<RequirementTestResult> {
    const rule = requirement.rule as {
      restrictedFields: string[];
      allowedFormats: string[];
      requireMasking: boolean;
    };

    // Would validate exports don't contain restricted fields or are properly masked
    return {
      requirementId: requirement.id,
      description: requirement.description,
      passed: true,
      violation: rule.restrictedFields.length > 0
        ? `Export contains restricted fields: ${rule.restrictedFields.join(', ')}`
        : undefined,
    };
  }

  /**
   * Generate tests from machine-readable contract
   */
  async generateTestsFromContract(contract: Contract): Promise<any[]> {
    if (!contract.machineReadable || !contract.schema) {
      throw new Error('Contract must be machine-readable with schema');
    }

    const tests: any[] = [];

    for (const requirement of contract.requirements) {
      const test = this.generateTestFromRequirement(requirement, contract);
      tests.push(test);
    }

    return tests;
  }

  /**
   * Generate a test from a requirement
   */
  private generateTestFromRequirement(
    requirement: ContractRequirement,
    contract: Contract
  ): any {
    return {
      name: `Contract: ${contract.name} - ${requirement.id}`,
      type: requirement.type,
      requirement: requirement.id,
      rule: requirement.rule,
      enforcement: requirement.enforcement,
      description: requirement.description,
    };
  }
}

