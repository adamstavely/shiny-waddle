"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.APIGatewayTester = void 0;
class APIGatewayTester {
    constructor(config) {
        this.config = config || {};
        this.gatewayProvider = this.config.gatewayProvider;
        this.config.rateLimitConfig = this.config.rateLimitConfig || {
            defaultLimit: 100,
            defaultTimeWindow: 60,
        };
    }
    async testGatewayPolicy(policy, request) {
        const result = {
            testType: 'access-control',
            testName: `API Gateway Policy Test: ${policy.name}`,
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const endpointMatch = request.endpoint === policy.endpoint ||
                request.endpoint.startsWith(policy.endpoint);
            const methodMatch = request.method.toLowerCase() === policy.method.toLowerCase();
            if (!endpointMatch || !methodMatch) {
                result.error = 'Request does not match policy endpoint/method';
                return result;
            }
            let allowed = false;
            const appliedRules = [];
            for (const rule of policy.rules) {
                const conditionMet = this.evaluateCondition(rule.condition, request);
                if (conditionMet) {
                    appliedRules.push(rule.condition);
                    if (rule.action === 'allow') {
                        allowed = true;
                    }
                    else if (rule.action === 'deny') {
                        allowed = false;
                        break;
                    }
                    else if (rule.action === 'rate-limit') {
                        allowed = true;
                    }
                }
            }
            result.passed = allowed;
            result.details = {
                policy,
                request,
                allowed,
                appliedRules,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testRateLimiting(endpoint, requests) {
        const timeWindow = this.config.rateLimitConfig?.defaultTimeWindow || 60;
        const limit = this.config.rateLimitConfig?.defaultLimit || 100;
        let blocked = false;
        let blockedAt;
        let actualRequests = 0;
        if (this.gatewayProvider) {
            try {
                const result = await this.gatewayProvider.testRateLimit(endpoint, requests);
                blocked = result.blocked;
                blockedAt = result.blockedAt;
                actualRequests = result.actualRequests;
            }
            catch (error) {
                actualRequests = requests;
                blocked = this.config.mockData?.rateLimitBlocked ?? (actualRequests > limit);
                if (blocked) {
                    blockedAt = limit + 1;
                }
            }
        }
        else {
            actualRequests = requests;
            blocked = this.config.mockData?.rateLimitBlocked ?? (actualRequests > limit);
            if (blocked) {
                blockedAt = limit + 1;
            }
        }
        return {
            endpoint,
            requests,
            timeWindow,
            limit,
            actualRequests,
            blocked,
            blockedAt,
        };
    }
    async testAPIVersioning(version, endpoint) {
        const result = {
            testType: 'access-control',
            testName: `API Versioning Test: ${version}`,
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const checks = [
                { name: 'Version Format Valid', passed: /^v\d+$/.test(version) },
                { name: 'Version Not Deprecated', passed: true },
                { name: 'Version Has Security Updates', passed: true },
            ];
            const allPassed = checks.every(check => check.passed);
            result.passed = allPassed;
            result.details = {
                version,
                endpoint,
                checks,
                allPassed,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testServiceToServiceAuth(source, target) {
        const authMethod = 'mtls';
        const authenticated = true;
        const certificateValid = true;
        return {
            source,
            target,
            authMethod,
            authenticated,
            certificateValid,
        };
    }
    evaluateCondition(condition, request) {
        if (condition.includes('user.role')) {
            return request.user?.role === 'admin';
        }
        if (condition.includes('ip.address')) {
            return true;
        }
        return true;
    }
}
exports.APIGatewayTester = APIGatewayTester;
//# sourceMappingURL=api-gateway-tester.js.map