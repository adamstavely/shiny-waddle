"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SensitiveDataTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const pii_detector_1 = require("../utils/pii-detector");
const credential_detector_1 = require("../utils/credential-detector");
class SensitiveDataTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testPIIExposure(endpoint, method, test));
        results.push(await this.testCredentialExposure(endpoint, method, test));
        results.push(await this.testErrorInformationDisclosure(endpoint, method, test));
        results.push(await this.testStackTraceExposure(endpoint, method, test));
        results.push(await this.testDebugEndpoints(endpoint, method, test));
        results.push(await this.testBackupFiles(endpoint, method, test));
        results.push(await this.testAPIVersioning(endpoint, method, test));
        return results;
    }
    async testPIIExposure(endpoint, method, test) {
        const result = this.createBaseResult('PII Exposure Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseText = await response.text();
            const responseJson = await response.json().catch(() => null);
            const piiDetection = responseJson ? (0, pii_detector_1.detectPIIInJSON)(responseJson) : (0, pii_detector_1.detectPII)(responseText);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !piiDetection.detected;
            result.securityIssues = piiDetection.detected ? [`PII detected: ${piiDetection.piiTypes.join(', ')}`] : undefined;
            result.details = {
                piiTypes: piiDetection.piiTypes,
                matches: piiDetection.matches.slice(0, 5),
                severity: piiDetection.severity,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testCredentialExposure(endpoint, method, test) {
        const result = this.createBaseResult('Credential Exposure Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const response = await this.makeRequest(url, method, headers);
            const responseText = await response.text();
            const responseJson = await response.json().catch(() => null);
            const credentialDetection = responseJson ? (0, credential_detector_1.detectCredentialsInJSON)(responseJson) : (0, credential_detector_1.detectCredentials)(responseText);
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !credentialDetection.detected;
            result.securityIssues = credentialDetection.detected ? [`Credentials detected: ${credentialDetection.credentialTypes.join(', ')}`] : undefined;
            result.details = {
                credentialTypes: credentialDetection.credentialTypes,
                matches: credentialDetection.matches.slice(0, 5),
                severity: credentialDetection.severity,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testErrorInformationDisclosure(endpoint, method, test) {
        const result = this.createBaseResult('Error Information Disclosure Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const invalidBodies = [
                { id: null },
                { id: 'invalid' },
                { id: -1 },
            ];
            const securityIssues = [];
            for (const body of invalidBodies) {
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                const sensitivePatterns = [
                    /sql/i,
                    /database/i,
                    /connection string/i,
                    /file path/i,
                    /stack trace/i,
                    /exception/i,
                    /error at/i,
                ];
                for (const pattern of sensitivePatterns) {
                    if (pattern.test(responseText)) {
                        securityIssues.push(`Error message contains sensitive information: ${pattern.source}`);
                        break;
                    }
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                errorsTested: invalidBodies.length,
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
    async testStackTraceExposure(endpoint, method, test) {
        const result = this.createBaseResult('Stack Trace Exposure Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const body = { invalid: 'data' };
            const response = await this.makeRequest(url, method, headers, body);
            const responseText = await response.text();
            const stackTracePatterns = [
                /at\s+\w+\.\w+/,
                /stack trace/i,
                /traceback/i,
                /\.java:\d+/,
                /\.py:\d+/,
                /\.js:\d+/,
                /line \d+/,
            ];
            const hasStackTrace = stackTracePatterns.some(pattern => pattern.test(responseText));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !hasStackTrace;
            result.securityIssues = hasStackTrace ? ['Stack trace exposed in response'] : undefined;
            result.details = {
                stackTraceDetected: hasStackTrace,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testDebugEndpoints(endpoint, method, test) {
        const result = this.createBaseResult('Debug Endpoints Test', endpoint, method);
        const startTime = Date.now();
        try {
            const baseUrl = this.config.baseUrl;
            const headers = this.buildHeaders(test);
            const debugEndpoints = [
                '/debug',
                '/debug/',
                '/api/debug',
                '/_debug',
                '/.env',
                '/.git/config',
                '/phpinfo.php',
                '/test',
                '/testing',
            ];
            const securityIssues = [];
            for (const debugEndpoint of debugEndpoints) {
                const url = `${baseUrl}${debugEndpoint}`;
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    securityIssues.push(`Debug endpoint accessible: ${debugEndpoint}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                endpointsTested: debugEndpoints.length,
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
    async testBackupFiles(endpoint, method, test) {
        const result = this.createBaseResult('Backup Files Test', endpoint, method);
        const startTime = Date.now();
        try {
            const baseUrl = this.config.baseUrl;
            const headers = this.buildHeaders(test);
            const backupFiles = [
                '/.env.backup',
                '/config.json.bak',
                '/database.sql.bak',
                '/backup.sql',
                '/.git/config',
                '/.htaccess.bak',
            ];
            const securityIssues = [];
            for (const backupFile of backupFiles) {
                const url = `${baseUrl}${backupFile}`;
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    securityIssues.push(`Backup file accessible: ${backupFile}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                filesTested: backupFiles.length,
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
    async testAPIVersioning(endpoint, method, test) {
        const result = this.createBaseResult('API Versioning Test', endpoint, method);
        const startTime = Date.now();
        try {
            const baseUrl = this.config.baseUrl;
            const headers = this.buildHeaders(test);
            const deprecatedVersions = [
                '/v1/',
                '/v0/',
                '/api/v1/',
                '/api/v0/',
            ];
            const securityIssues = [];
            for (const version of deprecatedVersions) {
                const url = `${baseUrl}${version}${endpoint.replace(/^\//, '')}`;
                const response = await this.makeRequest(url, method, headers);
                if (response.status === 200) {
                    securityIssues.push(`Deprecated API version accessible: ${version}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                versionsTested: deprecatedVersions.length,
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
}
exports.SensitiveDataTestSuite = SensitiveDataTestSuite;
//# sourceMappingURL=sensitive-data-test-suite.js.map