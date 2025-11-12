"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyAsCode = void 0;
const policy_versioning_1 = require("./policy-versioning");
const fs = require("fs/promises");
const path = require("path");
let yaml;
try {
    yaml = require('js-yaml');
}
catch {
    try {
        yaml = require('yaml');
    }
    catch {
    }
}
class PolicyAsCode {
    constructor(policiesDir = './policies', config = {}) {
        this.policiesDir = policiesDir;
        this.versioning = new policy_versioning_1.PolicyVersioning(path.join(policiesDir, 'versions'));
        this.config = {
            format: config.format || 'json',
            versioning: config.versioning !== false,
            testing: config.testing || { enabled: true },
            enforcement: config.enforcement || {
                enabled: false,
                mode: 'inline',
            },
        };
    }
    async loadPolicy(filePath) {
        const content = await fs.readFile(filePath, 'utf-8');
        const ext = path.extname(filePath).toLowerCase();
        if (ext === '.yaml' || ext === '.yml') {
            return this.loadYAMLPolicy(content, filePath);
        }
        else if (ext === '.rego') {
            return this.loadRegoPolicy(content, filePath);
        }
        else {
            return this.loadJSONPolicy(content, filePath);
        }
    }
    loadYAMLPolicy(content, filePath) {
        if (!yaml) {
            throw new Error('YAML support not available. Install js-yaml or yaml package.');
        }
        try {
            const parsed = yaml.load(content);
            if (parsed.policies) {
                return {
                    policies: parsed.policies.map((p) => this.normalizePolicy(p)),
                    format: 'yaml',
                    metadata: parsed.metadata,
                };
            }
            else if (Array.isArray(parsed)) {
                return {
                    policies: parsed.map((p) => this.normalizePolicy(p)),
                    format: 'yaml',
                };
            }
            else if (parsed.id) {
                return {
                    policies: [this.normalizePolicy(parsed)],
                    format: 'yaml',
                };
            }
            else {
                throw new Error('Invalid YAML policy format');
            }
        }
        catch (error) {
            throw new Error(`Failed to parse YAML policy: ${error.message}`);
        }
    }
    loadJSONPolicy(content, filePath) {
        try {
            const parsed = JSON.parse(content);
            if (parsed.policies) {
                return {
                    policies: parsed.policies.map((p) => this.normalizePolicy(p)),
                    format: 'json',
                    metadata: parsed.metadata,
                };
            }
            else if (Array.isArray(parsed)) {
                return {
                    policies: parsed.map((p) => this.normalizePolicy(p)),
                    format: 'json',
                };
            }
            else if (parsed.id) {
                return {
                    policies: [this.normalizePolicy(parsed)],
                    format: 'json',
                };
            }
            else {
                throw new Error('Invalid JSON policy format');
            }
        }
        catch (error) {
            throw new Error(`Failed to parse JSON policy: ${error.message}`);
        }
    }
    loadRegoPolicy(content, filePath) {
        const policyId = path.basename(filePath, '.rego');
        return {
            policies: [
                {
                    id: policyId,
                    name: `Rego Policy: ${policyId}`,
                    description: 'Rego policy loaded from file',
                    effect: 'allow',
                    conditions: [],
                    priority: 0,
                    metadata: {
                        format: 'rego',
                        regoCode: content,
                    },
                },
            ],
            format: 'rego',
        };
    }
    normalizePolicy(policy) {
        return {
            id: policy.id || `policy-${Date.now()}`,
            name: policy.name || policy.id || 'Unnamed Policy',
            description: policy.description,
            effect: policy.effect || 'allow',
            priority: policy.priority || 0,
            conditions: policy.conditions || [],
            metadata: policy.metadata,
        };
    }
    async savePolicy(policies, filePath, format = 'json') {
        await fs.mkdir(path.dirname(filePath), { recursive: true });
        if (format === 'yaml') {
            if (!yaml) {
                throw new Error('YAML support not available. Install js-yaml or yaml package.');
            }
            const yamlContent = yaml.dump(policies.length === 1 ? policies[0] : { policies }, { indent: 2 });
            await fs.writeFile(filePath, yamlContent);
        }
        else {
            const jsonContent = policies.length === 1
                ? JSON.stringify(policies[0], null, 2)
                : JSON.stringify({ policies }, null, 2);
            await fs.writeFile(filePath, jsonContent);
        }
        if (this.config.versioning) {
            await this.versioning.createVersion(policies, `Policy saved to ${filePath}`, process.env.USER || 'system');
        }
    }
    async testPolicy(policy, testCases, evaluator) {
        const results = [];
        const errors = [];
        const warnings = [];
        for (const testCase of testCases) {
            try {
                const actual = await evaluator(testCase.request);
                const passed = actual.allowed === testCase.expected.allowed;
                results.push({
                    ...testCase,
                    actual,
                    passed,
                });
                if (!passed) {
                    errors.push(`Test "${testCase.name}" failed: expected ${testCase.expected.allowed}, got ${actual.allowed}`);
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
    async enforcePolicy(policy, enforcementPoint) {
        if (!this.config.enforcement.enabled) {
            return {
                policyId: policy.id,
                enforced: false,
                enforcementPoint,
                mode: this.config.enforcement.mode,
                timestamp: new Date(),
                errors: ['Policy enforcement is not enabled'],
            };
        }
        try {
            const enforced = await this.deployToEnforcementPoint(policy, enforcementPoint, this.config.enforcement.mode);
            return {
                policyId: policy.id,
                enforced,
                enforcementPoint,
                mode: this.config.enforcement.mode,
                timestamp: new Date(),
            };
        }
        catch (error) {
            return {
                policyId: policy.id,
                enforced: false,
                enforcementPoint,
                mode: this.config.enforcement.mode,
                timestamp: new Date(),
                errors: [error.message],
            };
        }
    }
    async deployToEnforcementPoint(policy, enforcementPoint, mode) {
        switch (mode) {
            case 'gatekeeper':
                return this.deployAsGatekeeperPolicy(policy, enforcementPoint);
            case 'admission-controller':
                return this.deployAsAdmissionController(policy, enforcementPoint);
            case 'sidecar':
                return this.deployAsSidecar(policy, enforcementPoint);
            case 'inline':
                return true;
            default:
                throw new Error(`Unsupported enforcement mode: ${mode}`);
        }
    }
    async deployAsGatekeeperPolicy(policy, enforcementPoint) {
        console.log(`Deploying policy ${policy.id} as Gatekeeper policy to ${enforcementPoint}`);
        return true;
    }
    async deployAsAdmissionController(policy, enforcementPoint) {
        console.log(`Deploying policy ${policy.id} as admission controller to ${enforcementPoint}`);
        return true;
    }
    async deployAsSidecar(policy, enforcementPoint) {
        console.log(`Deploying policy ${policy.id} as sidecar to ${enforcementPoint}`);
        return true;
    }
    async convertPolicy(policy, targetFormat) {
        switch (targetFormat) {
            case 'json':
                return JSON.stringify(policy, null, 2);
            case 'yaml':
                if (!yaml) {
                    throw new Error('YAML support not available. Install js-yaml or yaml package.');
                }
                return yaml.dump(policy, { indent: 2 });
            case 'rego':
                const { PolicyLanguageSupport } = await Promise.resolve().then(() => require('./policy-language-support'));
                const languageSupport = new PolicyLanguageSupport();
                const regoCode = languageSupport
                    .getAdapter('rego')
                    ?.convertFromABAC(policy);
                return typeof regoCode === 'string' ? regoCode : JSON.stringify(regoCode);
            default:
                throw new Error(`Unsupported target format: ${targetFormat}`);
        }
    }
    async validatePolicy(policy, format) {
        const errors = [];
        try {
            let parsedPolicy;
            if (typeof policy === 'string') {
                if (format === 'yaml' || format === undefined) {
                    try {
                        const loaded = await this.loadYAMLPolicy(policy, '');
                        parsedPolicy = loaded.policies[0];
                    }
                    catch (e) {
                        if (format === 'yaml')
                            throw e;
                        const loaded = await this.loadJSONPolicy(policy, '');
                        parsedPolicy = loaded.policies[0];
                    }
                }
                else if (format === 'json') {
                    const loaded = await this.loadJSONPolicy(policy, '');
                    parsedPolicy = loaded.policies[0];
                }
                else {
                    const { PolicyLanguageSupport } = await Promise.resolve().then(() => require('./policy-language-support'));
                    const languageSupport = new PolicyLanguageSupport();
                    const result = languageSupport.validate('rego', policy);
                    return result;
                }
            }
            else {
                parsedPolicy = policy;
            }
            if (!parsedPolicy.id) {
                errors.push('Policy must have an id');
            }
            if (!parsedPolicy.name) {
                errors.push('Policy must have a name');
            }
            if (!parsedPolicy.effect || !['allow', 'deny'].includes(parsedPolicy.effect)) {
                errors.push('Policy must have effect "allow" or "deny"');
            }
            if (!Array.isArray(parsedPolicy.conditions)) {
                errors.push('Policy must have conditions array');
            }
            return {
                valid: errors.length === 0,
                errors,
            };
        }
        catch (error) {
            return {
                valid: false,
                errors: [error.message],
            };
        }
    }
    async getVersionHistory(limit) {
        return this.versioning.getVersionHistory(limit);
    }
    async rollbackToVersion(version) {
        return this.versioning.rollback(version);
    }
}
exports.PolicyAsCode = PolicyAsCode;
//# sourceMappingURL=policy-as-code.js.map