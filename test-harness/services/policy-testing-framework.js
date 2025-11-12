"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyTestingFramework = void 0;
class PolicyTestingFramework {
    constructor(pdp) {
        this.pdp = pdp;
    }
    async runUnitTests(policy, testCases) {
        const results = [];
        const errors = [];
        const warnings = [];
        for (const testCase of testCases) {
            try {
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
                const passed = decision.allowed === testCase.expected.allowed;
                results.push({
                    ...testCase,
                    actual: {
                        allowed: decision.allowed,
                        reason: decision.reason,
                    },
                    passed,
                });
                if (!passed) {
                    errors.push(`Test "${testCase.name}" failed: expected ${testCase.expected.allowed}, got ${decision.allowed}. Reason: ${decision.reason}`);
                }
                else if (testCase.expected.reason && decision.reason !== testCase.expected.reason) {
                    warnings.push(`Test "${testCase.name}" passed but reason mismatch: expected "${testCase.expected.reason}", got "${decision.reason}"`);
                }
            }
            catch (error) {
                errors.push(`Test "${testCase.name}" error: ${error.message}`);
                results.push({
                    ...testCase,
                    passed: false,
                    actual: { allowed: false, reason: error.message },
                });
            }
        }
        return {
            policyId: policy.id,
            passed: errors.length === 0,
            testCases: results,
            errors,
            warnings,
        };
    }
    async runRegressionTests(policy, baselineResults, testCases) {
        const currentResults = new Map();
        const regressions = [];
        for (const testCase of testCases) {
            try {
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
                currentResults.set(testCase.name, decision.allowed);
                const baselineResult = baselineResults.get(testCase.name);
                if (baselineResult !== undefined && baselineResult !== decision.allowed) {
                    regressions.push({
                        testCase: testCase.name,
                        baselineResult,
                        currentResult: decision.allowed,
                    });
                }
            }
            catch (error) {
                currentResults.set(testCase.name, false);
                const baselineResult = baselineResults.get(testCase.name);
                if (baselineResult !== undefined && baselineResult !== false) {
                    regressions.push({
                        testCase: testCase.name,
                        baselineResult,
                        currentResult: false,
                    });
                }
            }
        }
        return {
            policyId: policy.id,
            baselineResults,
            currentResults,
            regressions,
        };
    }
    async runPerformanceTests(policy, testCase, iterations = 1000) {
        const times = [];
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
        for (let i = 0; i < 10; i++) {
            await this.pdp.evaluate(request);
        }
        for (let i = 0; i < iterations; i++) {
            const start = process.hrtime.bigint();
            await this.pdp.evaluate(request);
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
        return {
            policyId: policy.id,
            evaluationCount: iterations,
            totalTime,
            averageTime,
            minTime,
            maxTime,
            p50,
            p95,
            p99,
        };
    }
    generateTestCases(policy) {
        const testCases = [];
        for (const condition of policy.conditions) {
            testCases.push({
                name: `${policy.id}-${condition.attribute}-matches`,
                description: `Test that ${condition.attribute} matches condition`,
                request: {
                    subject: this.generateSubjectFromCondition(condition),
                    resource: this.generateResourceFromCondition(condition),
                    action: 'read',
                },
                expected: {
                    allowed: policy.effect === 'allow',
                },
                passed: false,
            });
            testCases.push({
                name: `${policy.id}-${condition.attribute}-no-match`,
                description: `Test that ${condition.attribute} doesn't match condition`,
                request: {
                    subject: this.generateSubjectFromCondition(condition, true),
                    resource: this.generateResourceFromCondition(condition, true),
                    action: 'read',
                },
                expected: {
                    allowed: policy.effect === 'deny',
                },
                passed: false,
            });
        }
        return testCases;
    }
    generateSubjectFromCondition(condition, negate = false) {
        const subject = { id: 'test-subject', attributes: {} };
        if (condition.attribute.startsWith('subject.')) {
            const attrName = condition.attribute.replace('subject.', '');
            if (negate) {
                subject.attributes[attrName] = `not-${condition.value}`;
            }
            else {
                subject.attributes[attrName] = condition.value;
            }
        }
        return subject;
    }
    generateResourceFromCondition(condition, negate = false) {
        const resource = { id: 'test-resource', type: 'test-resource-type', attributes: {} };
        if (condition.attribute.startsWith('resource.')) {
            const attrName = condition.attribute.replace('resource.', '');
            if (negate) {
                resource.attributes[attrName] = `not-${condition.value}`;
            }
            else {
                resource.attributes[attrName] = condition.value;
            }
        }
        return resource;
    }
    createTestSuite(name, policies, testCases) {
        return {
            id: `suite-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            name,
            policies,
            testCases,
            createdAt: new Date(),
            updatedAt: new Date(),
        };
    }
    async runTestSuite(suite) {
        const results = [];
        for (const policy of suite.policies) {
            const policyTestCases = suite.testCases.filter(tc => tc.name.startsWith(policy.id) || suite.testCases.length === 0);
            if (policyTestCases.length > 0) {
                const result = await this.runUnitTests(policy, policyTestCases);
                results.push(result);
            }
        }
        const total = results.reduce((sum, r) => sum + r.testCases.length, 0);
        const passed = results.reduce((sum, r) => sum + r.testCases.filter(tc => tc.passed).length, 0);
        const failed = total - passed;
        const passRate = total > 0 ? (passed / total) * 100 : 0;
        return {
            suiteId: suite.id,
            results,
            summary: {
                total,
                passed,
                failed,
                passRate,
            },
        };
    }
}
exports.PolicyTestingFramework = PolicyTestingFramework;
//# sourceMappingURL=policy-testing-framework.js.map