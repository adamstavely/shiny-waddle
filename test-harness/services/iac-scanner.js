"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IACScanner = void 0;
const fs = require("fs/promises");
class IACScanner {
    async scanTerraform(files) {
        const findings = [];
        for (const file of files) {
            try {
                const content = await fs.readFile(file, 'utf-8');
                const lines = content.split('\n');
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i];
                    const lineNum = i + 1;
                    if (this.detectHardcodedSecret(line)) {
                        findings.push({
                            file,
                            line: lineNum,
                            severity: 'critical',
                            type: 'hardcoded-secret',
                            description: 'Potential hardcoded secret detected',
                            recommendation: 'Use environment variables or secret management',
                        });
                    }
                    if (this.detectOverlyPermissive(line)) {
                        findings.push({
                            file,
                            line: lineNum,
                            severity: 'high',
                            type: 'overly-permissive',
                            description: 'Overly permissive access configuration',
                            recommendation: 'Apply principle of least privilege',
                        });
                    }
                    if (this.detectMissingPolicy(line)) {
                        findings.push({
                            file,
                            line: lineNum,
                            severity: 'medium',
                            type: 'missing-policy',
                            description: 'Missing access control policy',
                            recommendation: 'Add explicit access control policies',
                        });
                    }
                }
            }
            catch (error) {
                findings.push({
                    file,
                    line: 0,
                    severity: 'low',
                    type: 'insecure-config',
                    description: `Error reading file: ${error.message}`,
                    recommendation: 'Fix file access issues',
                });
            }
        }
        return {
            files,
            findings,
            passed: findings.filter(f => f.severity === 'critical' || f.severity === 'high').length === 0,
        };
    }
    async scanCloudFormation(templates) {
        return this.scanTerraform(templates);
    }
    async scanFiles(files) {
        const terraformFiles = files.filter(f => f.endsWith('.tf') || f.endsWith('.tfvars'));
        const cloudFormationFiles = files.filter(f => f.includes('cloudformation') || f.endsWith('.cfn') || f.endsWith('.template'));
        const results = [];
        if (terraformFiles.length > 0) {
            results.push(await this.scanTerraform(terraformFiles));
        }
        if (cloudFormationFiles.length > 0) {
            results.push(await this.scanCloudFormation(cloudFormationFiles));
        }
        const allFiles = [...new Set(results.flatMap(r => r.files))];
        const allFindings = results.flatMap(r => r.findings);
        const allPassed = results.every(r => r.passed);
        return {
            files: allFiles,
            findings: allFindings,
            passed: allPassed,
        };
    }
    async validateAccessControl(iacConfig) {
        const issues = [];
        if (!iacConfig.access_control) {
            issues.push({
                severity: 'high',
                type: 'missing-policy',
                description: 'Missing access control configuration',
            });
        }
        return issues;
    }
    detectHardcodedSecret(line) {
        const patterns = [
            /password\s*=\s*["'][^"']+["']/i,
            /secret\s*=\s*["'][^"']+["']/i,
            /api[_-]?key\s*=\s*["'][^"']+["']/i,
            /token\s*=\s*["'][^"']+["']/i,
        ];
        return patterns.some(pattern => pattern.test(line));
    }
    detectOverlyPermissive(line) {
        const patterns = [
            /action\s*=\s*["']\*["']/i,
            /principal\s*=\s*["']\*["']/i,
            /effect\s*=\s*["']allow["'].*resource\s*=\s*["']\*["']/i,
        ];
        return patterns.some(pattern => pattern.test(line));
    }
    detectMissingPolicy(line) {
        const resourcePattern = /resource\s+["'][^"']+["']/i;
        const policyPattern = /policy|access[_-]?control|permission/i;
        return resourcePattern.test(line) && !policyPattern.test(line);
    }
}
exports.IACScanner = IACScanner;
//# sourceMappingURL=iac-scanner.js.map