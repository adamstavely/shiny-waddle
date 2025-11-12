"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AccessControlTester = void 0;
const policy_decision_point_1 = require("./policy-decision-point");
class AccessControlTester {
    constructor(config) {
        this.config = config;
        this.pdp = new policy_decision_point_1.PolicyDecisionPoint(config);
    }
    async testPDPDecision(input) {
        const startTime = Date.now();
        const subjectAttributes = {
            role: input.user.role,
            ...input.user.attributes,
            ...(input.user.abacAttributes || {}),
        };
        const decision = await this.pdp.evaluate({
            subject: {
                id: input.user.id,
                attributes: subjectAttributes,
            },
            resource: {
                id: input.resource.id,
                type: input.resource.type,
                attributes: {
                    ...input.resource.attributes,
                    ...(input.resource.abacAttributes || {}),
                },
            },
            context: input.context,
        });
        const latency = Date.now() - startTime;
        return {
            allowed: decision.allowed,
            expectedAllowed: input.expectedDecision,
            decisionReason: decision.reason,
            policyRules: decision.appliedRules,
            timestamp: new Date(),
            latency,
        };
    }
    async testAccessScenarios(scenarios) {
        const results = [];
        for (const scenario of scenarios) {
            const result = await this.testPDPDecision(scenario);
            results.push(result);
        }
        return results;
    }
    async detectPolicyViolations(user, resource, context) {
        const violations = [];
        const decision = await this.pdp.evaluate({
            subject: {
                id: user.id,
                attributes: {
                    role: user.role,
                    ...user.attributes,
                },
            },
            resource: {
                id: resource.id,
                type: resource.type,
                attributes: resource.attributes,
            },
            context,
        });
        if (decision.allowed && resource.sensitivity === 'restricted' && user.role === 'viewer') {
            violations.push('Over-broad access: Viewer accessing restricted resource');
        }
        if (decision.allowed && !context.ipAddress && resource.sensitivity === 'confidential') {
            violations.push('Missing context restriction: No IP address validation for confidential resource');
        }
        if (decision.allowed && !context.timeOfDay && resource.sensitivity === 'restricted') {
            violations.push('Missing time-based restriction: No time-of-day validation for restricted resource');
        }
        return violations;
    }
    async validateDecisionConsistency(testCases) {
        const inconsistencies = [];
        const results = await this.testAccessScenarios(testCases);
        const groupedResults = new Map();
        for (let i = 0; i < testCases.length; i++) {
            const key = `${testCases[i].user.role}-${testCases[i].resource.type}`;
            if (!groupedResults.has(key)) {
                groupedResults.set(key, []);
            }
            groupedResults.get(key).push(results[i]);
        }
        for (const [key, groupResults] of groupedResults) {
            const allowedValues = new Set(groupResults.map(r => r.allowed));
            if (allowedValues.size > 1) {
                inconsistencies.push(`Inconsistent decisions for ${key}: found both allowed and denied`);
            }
        }
        return {
            consistent: inconsistencies.length === 0,
            inconsistencies,
        };
    }
}
exports.AccessControlTester = AccessControlTester;
//# sourceMappingURL=access-control-tester.js.map