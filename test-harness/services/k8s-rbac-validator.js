"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.K8sRBACValidator = void 0;
const fs = require("fs/promises");
class K8sRBACValidator {
    async validateFiles(files) {
        const rules = [];
        let namespace = 'default';
        for (const file of files) {
            try {
                const content = await fs.readFile(file, 'utf-8');
                const yaml = this.parseYAML(content);
                if (yaml.kind === 'Role' || yaml.kind === 'ClusterRole') {
                    namespace = yaml.metadata?.namespace || 'default';
                    if (yaml.rules) {
                        for (const rule of yaml.rules) {
                            const allowed = this.validateRule(rule);
                            rules.push({
                                resources: rule.resources || [],
                                verbs: rule.verbs || [],
                                allowed,
                                reason: allowed ? undefined : 'Overly permissive RBAC rule',
                            });
                        }
                    }
                }
            }
            catch (error) {
                rules.push({
                    resources: [],
                    verbs: [],
                    allowed: false,
                    reason: `Error parsing file: ${error.message}`,
                });
            }
        }
        const passed = rules.every(r => r.allowed);
        return {
            namespace,
            role: 'validated-role',
            rules,
            passed,
        };
    }
    validateRule(rule) {
        if (rule.resources && rule.resources.includes('*')) {
            return false;
        }
        if (rule.verbs && rule.verbs.includes('*')) {
            return false;
        }
        const dangerousVerbs = ['*', 'create', 'update', 'patch', 'delete'];
        const hasDangerousVerbs = rule.verbs?.some((v) => dangerousVerbs.includes(v.toLowerCase()));
        if (hasDangerousVerbs && rule.resources?.includes('*')) {
            return false;
        }
        return true;
    }
    parseYAML(content) {
        const lines = content.split('\n');
        const result = {};
        for (const line of lines) {
            if (line.includes('kind:')) {
                result.kind = line.split(':')[1].trim().replace(/['"]/g, '');
            }
            if (line.includes('namespace:')) {
                if (!result.metadata)
                    result.metadata = {};
                result.metadata.namespace = line.split(':')[1].trim().replace(/['"]/g, '');
            }
            if (line.includes('resources:') || line.includes('verbs:')) {
                if (!result.rules)
                    result.rules = [{}];
                const key = line.split(':')[0].trim();
                const value = line.split(':')[1].trim().replace(/['"\[\]]/g, '');
                if (!result.rules[0][key]) {
                    result.rules[0][key] = [];
                }
                result.rules[0][key].push(value);
            }
        }
        return result;
    }
}
exports.K8sRBACValidator = K8sRBACValidator;
//# sourceMappingURL=k8s-rbac-validator.js.map