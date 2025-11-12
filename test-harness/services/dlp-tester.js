"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DLPTester = void 0;
class DLPTester {
    constructor(config) {
        this.patterns = [];
        if (Array.isArray(config)) {
            this.patterns = config.length > 0 ? config : this.getDefaultPatterns();
            this.config = {};
        }
        else {
            this.config = config || {};
            this.patterns = this.config.patterns || this.getDefaultPatterns();
        }
        if (this.config.piiDetectionRules) {
            this.config.piiDetectionRules.forEach(rule => {
                this.patterns.push({
                    name: `Custom PII: ${rule.fieldName}`,
                    type: 'regex',
                    pattern: rule.pattern.source,
                    severity: rule.severity,
                });
            });
        }
    }
    async testDataExfiltration(user, dataOperation) {
        const result = {
            testType: 'data-behavior',
            testName: 'Data Exfiltration Test',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const detectedPatterns = this.detectSensitiveData(dataOperation.data, this.patterns);
            const exfiltrationTest = {
                user,
                operation: dataOperation.type === 'export' ? 'export' :
                    dataOperation.type === 'read' ? 'query' : 'api-call',
                dataSize: this.calculateDataSize(dataOperation.data),
                detected: detectedPatterns.length > 0,
                pattern: detectedPatterns.length > 0 ? detectedPatterns[0] : undefined,
            };
            result.passed = !exfiltrationTest.detected;
            result.details = {
                exfiltrationTest,
                detectedPatterns,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async validateAPIResponse(apiResponse, allowedFields, piiFields) {
        const result = {
            testType: 'data-behavior',
            testName: 'API Response Validation',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const violations = [];
            const responseFields = this.extractFields(apiResponse);
            const leakedPII = responseFields.filter(field => piiFields.includes(field) && !allowedFields.includes(field));
            if (leakedPII.length > 0) {
                violations.push(`PII fields leaked: ${leakedPII.join(', ')}`);
            }
            const disallowedFields = responseFields.filter(field => !allowedFields.includes(field));
            if (disallowedFields.length > 0) {
                violations.push(`Disallowed fields in response: ${disallowedFields.join(', ')}`);
            }
            const sensitiveData = this.detectSensitiveData(apiResponse, this.patterns);
            if (sensitiveData.length > 0) {
                violations.push(`Sensitive data patterns detected: ${sensitiveData.map(p => p.name).join(', ')}`);
            }
            result.passed = violations.length === 0;
            result.details = {
                violations,
                responseFields,
                allowedFields,
                piiFields,
                sensitiveData,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testQueryResultValidation(query, user, expectedFields) {
        const result = {
            testType: 'data-behavior',
            testName: 'Query Result Validation',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const queryFields = this.extractQueryFields(query);
            const disallowedFields = queryFields.filter(field => !expectedFields.includes(field));
            result.passed = disallowedFields.length === 0;
            result.details = {
                query,
                user,
                queryFields,
                expectedFields,
                disallowedFields,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testBulkExportControls(user, exportRequest) {
        const result = {
            testType: 'data-behavior',
            testName: 'Bulk Export Controls Test',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const bulkExportTest = {
                user,
                exportType: exportRequest.type,
                recordCount: exportRequest.recordCount,
                allowed: false,
            };
            const defaultLimits = {
                admin: 100000,
                researcher: 10000,
                analyst: 5000,
                viewer: 1000,
            };
            const configuredLimit = this.config.bulkExportLimits?.[exportRequest.type];
            const roleBasedLimit = defaultLimits[user.role] || 1000;
            const userLimit = configuredLimit ?? roleBasedLimit;
            bulkExportTest.allowed = exportRequest.recordCount <= userLimit;
            if (!bulkExportTest.allowed) {
                bulkExportTest.reason = `Export exceeds limit of ${userLimit} records for role ${user.role}`;
            }
            result.passed = bulkExportTest.allowed;
            result.details = {
                bulkExportTest,
                userLimit,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async detectSensitiveDataLeakage(response, patterns) {
        const results = [];
        const detectedPatterns = this.detectSensitiveData(response, patterns);
        for (const pattern of detectedPatterns) {
            const result = {
                testType: 'data-behavior',
                testName: `Sensitive Data Detection: ${pattern.name}`,
                passed: false,
                details: {
                    pattern,
                    severity: pattern.severity,
                },
                timestamp: new Date(),
            };
            results.push(result);
        }
        return results;
    }
    getDefaultPatterns() {
        return [
            {
                name: 'Email Address',
                type: 'regex',
                pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
                severity: 'medium',
            },
            {
                name: 'SSN',
                type: 'regex',
                pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
                severity: 'critical',
            },
            {
                name: 'Credit Card',
                type: 'regex',
                pattern: '\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b',
                severity: 'critical',
            },
        ];
    }
    detectSensitiveData(data, patterns) {
        const detected = [];
        const dataString = JSON.stringify(data);
        for (const pattern of patterns) {
            if (pattern.type === 'regex') {
                const regex = new RegExp(pattern.pattern, 'gi');
                if (regex.test(dataString)) {
                    detected.push(pattern);
                }
            }
        }
        return detected;
    }
    calculateDataSize(data) {
        return JSON.stringify(data).length;
    }
    extractFields(obj, prefix = '') {
        const fields = [];
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                const fieldName = prefix ? `${prefix}.${key}` : key;
                if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                    fields.push(...this.extractFields(obj[key], fieldName));
                }
                else {
                    fields.push(fieldName);
                }
            }
        }
        return fields;
    }
    extractQueryFields(query) {
        const fields = [];
        if (query.sql) {
            const selectMatch = query.sql.match(/SELECT\s+(.+?)\s+FROM/i);
            if (selectMatch) {
                const selectClause = selectMatch[1];
                if (selectClause === '*') {
                    fields.push('*');
                }
                else {
                    const fieldMatches = selectClause.matchAll(/(\w+)/g);
                    for (const match of fieldMatches) {
                        fields.push(match[1]);
                    }
                }
            }
        }
        return fields;
    }
}
exports.DLPTester = DLPTester;
//# sourceMappingURL=dlp-tester.js.map