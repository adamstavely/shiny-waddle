"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseValidator = void 0;
class BaseValidator {
    constructor(config) {
        this.config = config || {};
        this.validateConfiguration();
    }
    canHandle(suite) {
        return this.shouldRun(suite);
    }
    async runTests(suite) {
        if (!this.canHandle(suite)) {
            return [];
        }
        try {
            return await this.runTestsInternal(suite);
        }
        catch (error) {
            return [{
                    testType: this.testType,
                    testName: `${this.name} - Error`,
                    passed: false,
                    details: {
                        error: error.message,
                        stack: error.stack,
                    },
                    timestamp: new Date(),
                    error: error.message,
                }];
        }
    }
    shouldRun(suite) {
        switch (this.testType) {
            case 'access-control':
                return suite.includeAccessControlTests === true;
            case 'dataset-health':
                return suite.includeDatasetHealthTests === true;
            default:
                return suite[`include${this.capitalize(this.testType)}Tests`] === true;
        }
    }
    validateConfiguration() {
        if (this.validateConfig) {
            const result = this.validateConfig(this.config);
            if (!result.valid) {
                throw new Error(`Invalid configuration for validator ${this.id}: ${result.errors.join(', ')}`);
            }
        }
    }
    createTestResult(testName, passed, details, error) {
        return {
            testType: this.testType,
            testName,
            passed,
            details,
            timestamp: new Date(),
            error,
        };
    }
    createPassedResult(testName, details) {
        return this.createTestResult(testName, true, details || {});
    }
    createFailedResult(testName, reason, details) {
        return this.createTestResult(testName, false, { reason, ...details }, reason);
    }
    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
}
exports.BaseValidator = BaseValidator;
//# sourceMappingURL=base-validator.js.map