"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContractTester = void 0;
const query_analyzer_1 = require("./query-analyzer");
class ContractTester {
    constructor(config) {
        this.config = config;
        this.queryAnalyzer = new query_analyzer_1.QueryAnalyzer({});
    }
    async testContract(contract) {
        const requirementResults = [];
        const violations = [];
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
    async testRequirement(requirement, contract) {
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
    async testFieldRestriction(requirement) {
        const rule = requirement.rule;
        return {
            requirementId: requirement.id,
            description: requirement.description,
            passed: true,
            violation: rule.allowed
                ? undefined
                : `Restricted fields accessed: ${rule.fields.join(', ')}`,
        };
    }
    async testAggregationRequirement(requirement) {
        const rule = requirement.rule;
        if (rule.requireAggregation && rule.minK > 0) {
            return {
                requirementId: requirement.id,
                description: requirement.description,
                passed: true,
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
    async testJoinRestriction(requirement) {
        const rule = requirement.rule;
        return {
            requirementId: requirement.id,
            description: requirement.description,
            passed: true,
            violation: rule.disallowedJoins.length > 0
                ? `Disallowed joins detected: ${rule.disallowedJoins.join(', ')}`
                : undefined,
        };
    }
    async testExportRestriction(requirement) {
        const rule = requirement.rule;
        return {
            requirementId: requirement.id,
            description: requirement.description,
            passed: true,
            violation: rule.restrictedFields.length > 0
                ? `Export contains restricted fields: ${rule.restrictedFields.join(', ')}`
                : undefined,
        };
    }
    async generateTestsFromContract(contract) {
        if (!contract.machineReadable || !contract.schema) {
            throw new Error('Contract must be machine-readable with schema');
        }
        const tests = [];
        for (const requirement of contract.requirements) {
            const test = this.generateTestFromRequirement(requirement, contract);
            tests.push(test);
        }
        return tests;
    }
    generateTestFromRequirement(requirement, contract) {
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
exports.ContractTester = ContractTester;
//# sourceMappingURL=contract-tester.js.map