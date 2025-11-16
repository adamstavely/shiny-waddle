"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Sentinel = void 0;
const user_simulator_1 = require("../services/user-simulator");
const access_control_tester_1 = require("../services/access-control-tester");
const dataset_health_tester_1 = require("../services/dataset-health-tester");
const compliance_reporter_1 = require("../services/compliance-reporter");
class Sentinel {
    constructor(config) {
        this.userSimulator = new user_simulator_1.UserSimulator(config.userSimulationConfig);
        this.accessControlTester = new access_control_tester_1.AccessControlTester(config.accessControlConfig);
        this.datasetHealthTester = new dataset_health_tester_1.DatasetHealthTester(config.datasetHealthConfig);
        this.complianceReporter = new compliance_reporter_1.ComplianceReporter(config.reportingConfig);
    }
    async runTestSuite(suite) {
        const results = [];
        if (suite.includeAccessControlTests) {
            const accessControlResults = await this.runAccessControlTests(suite);
            results.push(...accessControlResults);
        }
        if (suite.includeDatasetHealthTests) {
            const healthResults = await this.runDatasetHealthTests(suite);
            results.push(...healthResults);
        }
        return results;
    }
    async runAccessControlTests(suite) {
        const results = [];
        const testUsers = await this.userSimulator.generateTestUsers(suite.userRoles);
        for (const user of testUsers) {
            for (const resource of suite.resources) {
                for (const context of suite.contexts) {
                    const result = await this.accessControlTester.testPDPDecision({
                        user,
                        resource,
                        context,
                        expectedDecision: suite.expectedDecisions?.[`${user.role}-${resource.type}`],
                    });
                    results.push({
                        testType: 'access-control',
                        testName: `PDP Decision: ${user.role} accessing ${resource.type}`,
                        passed: result.allowed === result.expectedAllowed,
                        details: result,
                        timestamp: new Date(),
                    });
                }
            }
        }
        return results;
    }
    async runDatasetHealthTests(suite) {
        const results = [];
        for (const dataset of suite.datasets) {
            const result = await this.datasetHealthTester.testDataset({
                dataset,
                privacyThresholds: suite.privacyThresholds,
                statisticalFidelityTargets: suite.statisticalFidelityTargets,
            });
            results.push({
                testType: 'dataset-health',
                testName: `Dataset Health: ${dataset.name}`,
                passed: result.compliant,
                details: result,
                timestamp: new Date(),
            });
        }
        return results;
    }
    async generateComplianceReport(results) {
        return this.complianceReporter.generateReport(results);
    }
    isCompliant(results) {
        return results.every(result => result.passed);
    }
}
exports.Sentinel = Sentinel;
//# sourceMappingURL=test-harness.js.map