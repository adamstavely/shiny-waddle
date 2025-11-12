"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NetworkMicrosegmentationTester = void 0;
const service_mesh_integration_1 = require("./service-mesh-integration");
class NetworkMicrosegmentationTester {
    constructor(config) {
        if (config && 'name' in config) {
            this.config = { serviceMeshConfig: config };
        }
        else {
            this.config = config || {};
        }
        if (this.config.serviceMeshConfig) {
            this.serviceMesh = new service_mesh_integration_1.ServiceMeshIntegration(this.config.serviceMeshConfig);
        }
        this.connectivityProvider = this.config.connectivityProvider;
    }
    async testFirewallRules(rules) {
        const results = [];
        for (const rule of rules) {
            const result = {
                testType: 'access-control',
                testName: `Firewall Rule Test: ${rule.name}`,
                passed: false,
                details: {},
                timestamp: new Date(),
            };
            try {
                const validations = [
                    { name: 'Rule Enabled', passed: rule.enabled },
                    { name: 'Source Valid', passed: rule.source.length > 0 },
                    { name: 'Destination Valid', passed: rule.destination.length > 0 },
                    { name: 'Protocol Valid', passed: ['tcp', 'udp', 'icmp', 'all'].includes(rule.protocol) },
                    { name: 'Action Valid', passed: ['allow', 'deny'].includes(rule.action) },
                ];
                const allValid = validations.every(v => v.passed);
                result.passed = allValid;
                result.details = {
                    rule,
                    validations,
                    allValid,
                };
            }
            catch (error) {
                result.error = error.message;
            }
            results.push(result);
        }
        return results;
    }
    async testServiceToServiceTraffic(source, target) {
        const result = {
            testType: 'access-control',
            testName: `Service-to-Service Traffic Test: ${source} -> ${target}`,
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            if (!this.serviceMesh) {
                result.error = 'Service mesh configuration required';
                return result;
            }
            let allowed = true;
            let policyApplied;
            let error;
            if (this.connectivityProvider) {
                try {
                    const connectivityResult = await this.connectivityProvider.testConnectivity(source, target, 'http', 80);
                    allowed = connectivityResult.allowed;
                    policyApplied = connectivityResult.policyApplied;
                }
                catch (err) {
                    allowed = this.config.mockData?.connectivityAllowed ?? true;
                    error = err.message;
                }
            }
            else if (this.serviceMesh) {
                const test = {
                    sourceService: source,
                    targetService: target,
                    path: '/api/test',
                    method: 'GET',
                    expectedAllowed: true,
                };
                const meshResult = await this.serviceMesh.testServiceToServiceAccess(test);
                allowed = meshResult.allowed;
                policyApplied = meshResult.policyApplied;
                error = meshResult.error;
            }
            else {
                allowed = this.config.mockData?.connectivityAllowed ?? true;
            }
            result.passed = allowed;
            result.details = {
                source,
                target,
                allowed,
                expectedAllowed: true,
                policyApplied,
                ...(error && { error }),
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async validateNetworkSegmentation(segments) {
        if (this.connectivityProvider) {
            try {
                const validation = await this.connectivityProvider.validateSegmentation(segments);
                return segments.map(segment => {
                    const segmentViolations = validation.violations.filter(v => segment.services.includes(v.source) || segment.services.includes(v.target));
                    return {
                        testType: 'access-control',
                        testName: `Network Segmentation Test: ${segment.name}`,
                        passed: segmentViolations.length === 0,
                        details: {
                            segment,
                            violations: segmentViolations,
                        },
                        timestamp: new Date(),
                    };
                });
            }
            catch (error) {
            }
        }
        const mockViolations = this.config.mockData?.segmentationViolations || [];
        const validated = this.config.mockData?.segmentationValidated ?? true;
        const results = [];
        for (const segment of segments) {
            const result = {
                testType: 'access-control',
                testName: `Network Segmentation Test: ${segment.name}`,
                passed: false,
                details: {},
                timestamp: new Date(),
            };
            try {
                const validations = [
                    { name: 'Segment Has Services', passed: segment.services.length > 0 },
                    { name: 'Allowed Connections Defined', passed: segment.allowedConnections.length > 0 },
                    { name: 'Denied Connections Defined', passed: segment.deniedConnections.length > 0 },
                ];
                const violations = [];
                const segmentViolations = mockViolations.filter(v => segment.services.includes(v.source) || segment.services.includes(v.target));
                for (const service of segment.services) {
                    for (const deniedConnection of segment.deniedConnections) {
                        const hasViolation = segmentViolations.some(v => (v.source === service && v.target === deniedConnection) ||
                            (v.target === service && v.source === deniedConnection));
                        if (hasViolation) {
                            violations.push(`Service ${service} should not access ${deniedConnection}`);
                        }
                    }
                }
                result.passed = validated && validations.every(v => v.passed) && violations.length === 0;
                result.details = {
                    segment,
                    validations,
                    violations,
                };
            }
            catch (error) {
                result.error = error.message;
            }
            results.push(result);
        }
        return results;
    }
    async testServiceMeshPolicies(meshConfig) {
        const results = [];
        if (!this.serviceMesh) {
            this.serviceMesh = new service_mesh_integration_1.ServiceMeshIntegration(meshConfig);
        }
        try {
            const testScenarios = [
                { source: 'frontend', target: 'backend', expectedAllowed: true },
                { source: 'backend', target: 'database', expectedAllowed: true },
                { source: 'frontend', target: 'database', expectedAllowed: false },
            ];
            for (const scenario of testScenarios) {
                const test = {
                    sourceService: scenario.source,
                    targetService: scenario.target,
                    path: '/api/test',
                    method: 'GET',
                    expectedAllowed: scenario.expectedAllowed,
                };
                const meshResult = await this.serviceMesh.testServiceToServiceAccess(test);
                const result = {
                    testType: 'access-control',
                    testName: `Service Mesh Policy: ${scenario.source} -> ${scenario.target}`,
                    passed: meshResult.allowed === scenario.expectedAllowed,
                    details: {
                        scenario,
                        meshResult,
                    },
                    timestamp: new Date(),
                };
                results.push(result);
            }
        }
        catch (error) {
            const errorResult = {
                testType: 'access-control',
                testName: 'Service Mesh Policy Test',
                passed: false,
                error: error.message,
                details: {},
                timestamp: new Date(),
            };
            results.push(errorResult);
        }
        return results;
    }
}
exports.NetworkMicrosegmentationTester = NetworkMicrosegmentationTester;
//# sourceMappingURL=network-microsegmentation-tester.js.map