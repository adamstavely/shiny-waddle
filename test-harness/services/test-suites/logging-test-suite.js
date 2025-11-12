"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoggingTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const pii_detector_1 = require("../utils/pii-detector");
class LoggingTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testAuditLogging(endpoint, method, test));
        results.push(await this.testLogInjection(endpoint, method, test));
        results.push(await this.testSensitiveDataInLogs(endpoint, method, test));
        results.push(await this.testMonitoringCoverage(endpoint, method, test));
        return results;
    }
    async testAuditLogging(endpoint, method, test) {
        const result = this.createBaseResult('Audit Logging Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const auditIndicators = [
                'X-Audit-Log',
                'X-Request-ID',
                'X-Correlation-ID',
                'X-Trace-ID',
            ];
            const hasAuditLogging = auditIndicators.some(indicator => responseHeaders[indicator] || responseHeaders[indicator.toLowerCase()]);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = hasAuditLogging;
            result.securityIssues = !hasAuditLogging ? ['Audit logging may not be implemented'] : undefined;
            result.details = {
                auditIndicators,
                hasAuditLogging,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testLogInjection(endpoint, method, test) {
        const result = this.createBaseResult('Log Injection Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const securityIssues = [];
            const injectionPayloads = [
                '\n[CRITICAL] Security breach',
                '\r\n[ERROR] System compromised',
                '\x00[ALERT] Unauthorized access',
                'admin\n[INFO] Privilege escalation',
            ];
            for (const payload of injectionPayloads) {
                const body = { input: payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (responseText.includes('\n[CRITICAL]') ||
                    responseText.includes('\r\n[ERROR]') ||
                    responseText.includes('[ALERT]')) {
                    securityIssues.push(`Log injection possible: ${payload.substring(0, 20)}...`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: injectionPayloads.length,
                issuesFound: securityIssues.length,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testSensitiveDataInLogs(endpoint, method, test) {
        const result = this.createBaseResult('Sensitive Data in Logs Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseText = await response.text();
            const responseJson = await response.json().catch(() => null);
            const piiDetection = responseJson ? (0, pii_detector_1.detectPII)(JSON.stringify(responseJson)) : (0, pii_detector_1.detectPII)(responseText);
            const credentialDetection = responseJson ? (0, pii_detector_1.detectCredentials)(JSON.stringify(responseJson)) : (0, pii_detector_1.detectCredentials)(responseText);
            const securityIssues = [];
            if (piiDetection.detected && piiDetection.severity === 'critical') {
                securityIssues.push(`Critical PII detected in response (may be logged): ${piiDetection.piiTypes.join(', ')}`);
            }
            if (credentialDetection.detected && credentialDetection.severity === 'critical') {
                securityIssues.push(`Critical credentials detected in response (may be logged): ${credentialDetection.credentialTypes.join(', ')}`);
            }
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                piiDetected: piiDetection.detected,
                credentialsDetected: credentialDetection.detected,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testMonitoringCoverage(endpoint, method, test) {
        const result = this.createBaseResult('Monitoring Coverage Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseHeaders = Object.fromEntries(response.headers.entries());
            const monitoringIndicators = [
                'X-Request-ID',
                'X-Correlation-ID',
                'X-Trace-ID',
                'X-Response-Time',
            ];
            const hasMonitoring = monitoringIndicators.some(indicator => responseHeaders[indicator] || responseHeaders[indicator.toLowerCase()]);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = hasMonitoring;
            result.securityIssues = !hasMonitoring ? ['Monitoring may not be implemented'] : undefined;
            result.details = {
                monitoringIndicators,
                hasMonitoring,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
}
exports.LoggingTestSuite = LoggingTestSuite;
//# sourceMappingURL=logging-test-suite.js.map