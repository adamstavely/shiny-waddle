"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyValidationTester = void 0;
class PolicyValidationTester {
    constructor(config) {
        if (config && 'evaluate' in config) {
            this.pdp = config;
            this.config = {
                pdp: this.pdp,
                conflictDetection: {
                    checkPriority: true,
                    checkOverlap: true,
                    checkContradiction: true,
                },
                coverageAnalysis: {
                    minCoverage: 80,
                    generateRecommendations: true,
                },
                performanceTesting: {
                    iterations: 1000,
                    maxLatency: 100,
                },
            };
        }
        else {
            this.config = config;
            this.pdp = this.config.pdp;
            this.config.conflictDetection = {
                checkPriority: true,
                checkOverlap: true,
                checkContradiction: true,
                ...this.config.conflictDetection,
            };
            this.config.coverageAnalysis = {
                minCoverage: 80,
                generateRecommendations: true,
                ...this.config.coverageAnalysis,
            };
            this.config.performanceTesting = {
                iterations: 1000,
                maxLatency: 100,
                ...this.config.performanceTesting,
            };
        }
    }
    async detectPolicyConflicts(policies) {
        const conflicts = [];
        for (let i = 0; i < policies.length; i++) {
            for (let j = i + 1; j < policies.length; j++) {
                const policy1 = policies[i];
                const policy2 = policies[j];
                const overlap = this.detectOverlap(policy1, policy2);
                if (overlap.overlaps) {
                    if (this.config.conflictDetection?.checkContradiction &&
                        policy1.effect !== policy2.effect) {
                        conflicts.push({
                            policy1: policy1.id,
                            policy2: policy2.id,
                            conflictType: 'contradiction',
                            description: `Policies ${policy1.id} and ${policy2.id} have contradictory effects on overlapping conditions`,
                            affectedResources: overlap.resources,
                        });
                    }
                    else if (this.config.conflictDetection?.checkOverlap && overlap.overlaps) {
                        conflicts.push({
                            policy1: policy1.id,
                            policy2: policy2.id,
                            conflictType: 'overlap',
                            description: `Policies ${policy1.id} and ${policy2.id} have overlapping conditions`,
                            affectedResources: overlap.resources,
                        });
                    }
                }
                if (this.config.conflictDetection?.checkPriority &&
                    policy1.priority !== undefined && policy2.priority !== undefined) {
                    if (policy1.priority === policy2.priority && overlap.overlaps) {
                        conflicts.push({
                            policy1: policy1.id,
                            policy2: policy2.id,
                            conflictType: 'priority',
                            description: `Policies ${policy1.id} and ${policy2.id} have the same priority and overlapping conditions`,
                            affectedResources: overlap.resources,
                        });
                    }
                }
            }
        }
        return conflicts;
    }
    async analyzePolicyCoverage(resources, policies) {
        const resourcesWithPolicies = new Set();
        const resourcesWithoutPolicies = [];
        const gaps = [];
        for (const resource of resources) {
            const applicablePolicies = this.findApplicablePolicies(resource, policies);
            if (applicablePolicies.length > 0) {
                resourcesWithPolicies.add(resource.id);
            }
            else {
                resourcesWithoutPolicies.push(resource.id);
                gaps.push({
                    resource: resource.id,
                    resourceType: resource.type,
                    recommendedPolicy: this.generateRecommendedPolicy(resource),
                });
            }
        }
        const coveragePercentage = resources.length > 0
            ? (resourcesWithPolicies.size / resources.length) * 100
            : 0;
        return {
            totalResources: resources.length,
            resourcesWithPolicies: resourcesWithPolicies.size,
            resourcesWithoutPolicies,
            coveragePercentage,
            gaps,
        };
    }
    async testPolicyPerformance(policy, iterations) {
        const times = [];
        const testIterations = iterations ?? this.config.performanceTesting?.iterations ?? 1000;
        const maxLatency = this.config.performanceTesting?.maxLatency;
        const testRequest = this.generateTestRequest(policy);
        for (let i = 0; i < 10; i++) {
            await this.pdp.evaluate(testRequest);
        }
        for (let i = 0; i < testIterations; i++) {
            const start = process.hrtime.bigint();
            await this.pdp.evaluate(testRequest);
            const end = process.hrtime.bigint();
            const timeMs = Number(end - start) / 1_000_000;
            times.push(timeMs);
        }
        times.sort((a, b) => a - b);
        const totalTime = times.reduce((sum, t) => sum + t, 0);
        const averageTime = totalTime / times.length;
        const minTime = times[0];
        const maxTime = times[times.length - 1];
        const p50 = times[Math.floor(times.length * 0.5)];
        const p95 = times[Math.floor(times.length * 0.95)];
        const p99 = times[Math.floor(times.length * 0.99)];
        const result = {
            policyId: policy.id,
            evaluationCount: testIterations,
            totalTime,
            averageTime,
            minTime,
            maxTime,
            p50,
            p95,
            p99,
        };
        if (maxLatency && averageTime > maxLatency) {
        }
        return result;
    }
    async runRegressionTests(baselinePolicies, currentPolicies, testCases) {
        const baselinePDP = this.pdp;
        const currentPDP = this.pdp;
        const baselineResults = new Map();
        const currentResults = new Map();
        const regressions = [];
        for (const testCase of testCases) {
            const request = {
                subject: {
                    id: testCase.request.subject.id || 'test-subject',
                    attributes: testCase.request.subject.attributes || testCase.request.subject,
                },
                resource: {
                    id: testCase.request.resource.id || 'test-resource',
                    type: testCase.request.resource.type || 'test-resource-type',
                    attributes: testCase.request.resource.attributes || testCase.request.resource,
                },
                action: testCase.request.action || 'read',
                context: testCase.request.context || {},
            };
            const baselineDecision = await baselinePDP.evaluate(request);
            baselineResults.set(testCase.name, baselineDecision.allowed);
            const currentDecision = await currentPDP.evaluate(request);
            currentResults.set(testCase.name, currentDecision.allowed);
            if (baselineDecision.allowed !== currentDecision.allowed) {
                regressions.push({
                    testCase: testCase.name,
                    baselineResult: baselineDecision.allowed,
                    currentResult: currentDecision.allowed,
                });
            }
        }
        return {
            policyId: 'all-policies',
            baselineResults,
            currentResults,
            regressions,
        };
    }
    async simulatePolicyChange(policy, testCases) {
        const results = [];
        for (const testCase of testCases) {
            const request = {
                subject: {
                    id: testCase.request.subject.id || 'test-subject',
                    attributes: testCase.request.subject.attributes || testCase.request.subject,
                },
                resource: {
                    id: testCase.request.resource.id || 'test-resource',
                    type: testCase.request.resource.type || 'test-resource-type',
                    attributes: testCase.request.resource.attributes || testCase.request.resource,
                },
                action: testCase.request.action || 'read',
                context: testCase.request.context || {},
            };
            const decision = await this.pdp.evaluate(request);
            const match = decision.allowed === testCase.expected.allowed;
            results.push({
                name: testCase.name,
                request: testCase.request,
                expectedResult: testCase.expected.allowed,
                simulatedResult: decision.allowed,
                match,
            });
        }
        const overallMatch = results.every(r => r.match);
        return {
            policy,
            testCases: results,
            overallMatch,
        };
    }
    detectOverlap(policy1, policy2) {
        const resources = [];
        let overlaps = false;
        for (const condition1 of policy1.conditions) {
            for (const condition2 of policy2.conditions) {
                if (this.conditionsOverlap(condition1, condition2)) {
                    overlaps = true;
                    if (condition1.attribute.startsWith('resource.')) {
                        resources.push(condition1.attribute.replace('resource.', ''));
                    }
                    if (condition2.attribute.startsWith('resource.')) {
                        resources.push(condition2.attribute.replace('resource.', ''));
                    }
                }
            }
        }
        return { overlaps, resources: [...new Set(resources)] };
    }
    conditionsOverlap(condition1, condition2) {
        if (condition1.attribute === condition2.attribute) {
            return true;
        }
        if (condition1.attribute.includes('.') && condition2.attribute.includes('.')) {
            const parts1 = condition1.attribute.split('.');
            const parts2 = condition2.attribute.split('.');
            if (parts1[0] === parts2[0] && parts1.length > 1 && parts2.length > 1) {
                return true;
            }
        }
        return false;
    }
    findApplicablePolicies(resource, policies) {
        return policies.filter(policy => {
            return policy.conditions.some(condition => {
                if (condition.attribute.startsWith('resource.')) {
                    const attrName = condition.attribute.replace('resource.', '');
                    const resourceValue = resource.attributes[attrName] || resource.abacAttributes?.[attrName];
                    return this.evaluateCondition(condition, resourceValue);
                }
                return false;
            });
        });
    }
    evaluateCondition(condition, value) {
        switch (condition.operator) {
            case 'equals':
                return value === condition.value;
            case 'notEquals':
                return value !== condition.value;
            case 'in':
                return Array.isArray(condition.value) && condition.value.includes(value);
            case 'notIn':
                return Array.isArray(condition.value) && !condition.value.includes(value);
            default:
                return false;
        }
    }
    generateRecommendedPolicy(resource) {
        return `Allow access to ${resource.type} resources with appropriate conditions`;
    }
    generateTestRequest(policy) {
        const subject = { id: 'test-subject', attributes: {} };
        const resource = { id: 'test-resource', type: 'test-resource-type', attributes: {} };
        for (const condition of policy.conditions) {
            if (condition.attribute.startsWith('subject.')) {
                const attrName = condition.attribute.replace('subject.', '');
                subject.attributes[attrName] = condition.value;
            }
            else if (condition.attribute.startsWith('resource.')) {
                const attrName = condition.attribute.replace('resource.', '');
                resource.attributes[attrName] = condition.value;
            }
        }
        return {
            subject,
            resource,
            action: 'read',
            context: {},
        };
    }
}
exports.PolicyValidationTester = PolicyValidationTester;
//# sourceMappingURL=policy-validation-tester.js.map