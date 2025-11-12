"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComplianceReporter = void 0;
class ComplianceReporter {
    constructor(config) {
        this.config = config;
    }
    async generateReport(results) {
        const scores = this.calculateScores(results);
        const summary = this.generateSummary(results, scores);
        const report = {
            summary,
            scores,
            results,
            generatedAt: new Date().toISOString(),
        };
        if (this.config.outputPath) {
            await this.writeReport(report);
        }
        return report;
    }
    calculateScores(results) {
        const byCategory = {};
        const byApplication = {};
        const byTeam = {};
        for (const result of results) {
            if (!byCategory[result.testType]) {
                byCategory[result.testType] = { passed: 0, total: 0 };
            }
            byCategory[result.testType].total++;
            if (result.passed) {
                byCategory[result.testType].passed++;
            }
            const application = this.extractApplication(result);
            if (application) {
                if (!byApplication[application]) {
                    byApplication[application] = { passed: 0, total: 0 };
                }
                byApplication[application].total++;
                if (result.passed) {
                    byApplication[application].passed++;
                }
            }
            const team = this.extractTeam(result);
            if (team) {
                if (!byTeam[team]) {
                    byTeam[team] = { passed: 0, total: 0 };
                }
                byTeam[team].total++;
                if (result.passed) {
                    byTeam[team].passed++;
                }
            }
        }
        const overall = results.length > 0
            ? (results.filter(r => r.passed).length / results.length) * 100
            : 100;
        return {
            overall: Math.round(overall * 100) / 100,
            byCategory: Object.fromEntries(Object.entries(byCategory).map(([key, value]) => [
                key,
                value.total > 0 ? Math.round((value.passed / value.total) * 100 * 100) / 100 : 100,
            ])),
            byApplication: Object.fromEntries(Object.entries(byApplication).map(([key, value]) => [
                key,
                value.total > 0 ? Math.round((value.passed / value.total) * 100 * 100) / 100 : 100,
            ])),
            byTeam: Object.fromEntries(Object.entries(byTeam).map(([key, value]) => [
                key,
                value.total > 0 ? Math.round((value.passed / value.total) * 100 * 100) / 100 : 100,
            ])),
        };
    }
    generateSummary(results, scores) {
        const totalTests = results.length;
        const passedTests = results.filter(r => r.passed).length;
        const failedTests = totalTests - passedTests;
        const failuresByType = {};
        for (const result of results) {
            if (!result.passed) {
                failuresByType[result.testType] = (failuresByType[result.testType] || 0) + 1;
            }
        }
        return {
            totalTests,
            passedTests,
            failedTests,
            passRate: scores.overall,
            failuresByType,
            criticalFailures: results.filter(r => !r.passed && r.details?.severity === 'critical').length,
        };
    }
    extractApplication(result) {
        return result.details?.application || null;
    }
    extractTeam(result) {
        return result.details?.team || null;
    }
    async writeReport(report) {
        const fs = await Promise.resolve().then(() => require('fs/promises'));
        const path = await Promise.resolve().then(() => require('path'));
        let content;
        let extension;
        switch (this.config.outputFormat) {
            case 'json':
                content = JSON.stringify(report, null, 2);
                extension = 'json';
                break;
            case 'html':
                content = this.generateHtmlReport(report);
                extension = 'html';
                break;
            case 'junit':
                content = this.generateJunitReport(report);
                extension = 'xml';
                break;
            default:
                content = JSON.stringify(report, null, 2);
                extension = 'json';
        }
        const filePath = path.join(this.config.outputPath, `compliance-report-${Date.now()}.${extension}`);
        await fs.writeFile(filePath, content, 'utf-8');
    }
    generateHtmlReport(report) {
        return `
<!DOCTYPE html>
<html>
<head>
  <title>Compliance Test Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
    .score { font-size: 2em; font-weight: bold; color: #4CAF50; }
    .failed { color: #f44336; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background-color: #4CAF50; color: white; }
    .passed { color: #4CAF50; }
    .failed { color: #f44336; }
  </style>
</head>
<body>
  <h1>Compliance Test Report</h1>
  <div class="summary">
    <h2>Summary</h2>
    <p class="score ${report.summary.passRate < 100 ? 'failed' : ''}">
      ${report.summary.passRate}% Pass Rate
    </p>
    <p>Total Tests: ${report.summary.totalTests}</p>
    <p>Passed: ${report.summary.passedTests}</p>
    <p>Failed: ${report.summary.failedTests}</p>
  </div>
  <h2>Test Results</h2>
  <table>
    <tr>
      <th>Test Name</th>
      <th>Type</th>
      <th>Status</th>
      <th>Timestamp</th>
    </tr>
    ${report.results
            .map((r) => `
    <tr>
      <td>${r.testName}</td>
      <td>${r.testType}</td>
      <td class="${r.passed ? 'passed' : 'failed'}">${r.passed ? 'PASSED' : 'FAILED'}</td>
      <td>${r.timestamp.toISOString()}</td>
    </tr>
    `)
            .join('')}
  </table>
</body>
</html>
    `;
    }
    generateJunitReport(report) {
        const testsuites = report.results.map((r) => {
            return `    <testcase name="${r.testName}" classname="${r.testType}">
      ${!r.passed ? `<failure message="${r.error || 'Test failed'}"/>` : ''}
    </testcase>`;
        });
        return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Compliance Tests" tests="${report.summary.totalTests}" failures="${report.summary.failedTests}">
${testsuites.join('\n')}
  </testsuite>
</testsuites>`;
    }
}
exports.ComplianceReporter = ComplianceReporter;
//# sourceMappingURL=compliance-reporter.js.map