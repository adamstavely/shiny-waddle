"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServiceMeshIntegration = void 0;
class ServiceMeshIntegration {
    constructor(config) {
        this.config = config;
    }
    async testServiceToServiceAccess(test) {
        try {
            switch (this.config.type) {
                case 'istio':
                    return await this.testIstioAccess(test);
                case 'envoy':
                    return await this.testEnvoyAccess(test);
                default:
                    throw new Error(`Unsupported service mesh: ${this.config.type}`);
            }
        }
        catch (error) {
            return {
                test,
                allowed: false,
                error: error.message,
            };
        }
    }
    async testIstioAccess(test) {
        try {
            const policy = await this.getIstioPolicy(test);
            if (!policy) {
                return {
                    test,
                    allowed: true,
                };
            }
            const allowed = this.evaluateIstioPolicy(policy, test);
            return {
                test,
                allowed,
                policyApplied: policy.name,
            };
        }
        catch (error) {
            return {
                test,
                allowed: false,
                error: error.message,
            };
        }
    }
    async testEnvoyAccess(test) {
        try {
            const envoyAdminPort = this.config.options?.envoyAdminPort || 15000;
            const serviceName = test.targetService;
            const rbacConfig = await this.getEnvoyRBACConfig(serviceName, envoyAdminPort);
            if (!rbacConfig) {
                return {
                    test,
                    allowed: true,
                };
            }
            const allowed = this.evaluateEnvoyRBAC(rbacConfig, test);
            return {
                test,
                allowed,
                policyApplied: 'envoy-rbac',
            };
        }
        catch (error) {
            return {
                test,
                allowed: false,
                error: error.message,
            };
        }
    }
    async getEnvoyRBACConfig(serviceName, adminPort) {
        try {
            const response = await fetch(`http://${serviceName}:${adminPort}/config_dump?include_eds`, {
                headers: {
                    'Authorization': `Bearer ${this.config.credentials?.token || ''}`,
                },
            });
            if (!response.ok) {
                return null;
            }
            const config = await response.json();
            for (const configDump of config.configs || []) {
                if (configDump['@type']?.includes('listener')) {
                    const listeners = configDump.dynamic_listeners || configDump.static_listeners || [];
                    for (const listener of listeners) {
                        const filterChains = listener.filter_chains || [];
                        for (const chain of filterChains) {
                            const filters = chain.filters || [];
                            for (const filter of filters) {
                                if (filter.name === 'envoy.filters.network.rbac') {
                                    return filter.typed_config?.rules || null;
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }
        catch {
            return null;
        }
    }
    evaluateEnvoyRBAC(rbacConfig, test) {
        const policies = rbacConfig.policies || {};
        for (const [policyName, policy] of Object.entries(policies)) {
            const policyData = policy;
            const permissions = policyData.permissions || [];
            const principals = policyData.principals || [];
            const sourceMatches = this.matchesEnvoyPrincipals(principals, test.sourceService);
            const actionMatches = this.matchesEnvoyPermissions(permissions, test);
            if (sourceMatches && actionMatches) {
                return true;
            }
        }
        return false;
    }
    matchesEnvoyPrincipals(principals, sourceService) {
        for (const principal of principals) {
            if (principal.authenticated?.principal_name?.exact) {
                const expectedPrincipal = principal.authenticated.principal_name.exact;
                if (expectedPrincipal.includes(sourceService)) {
                    return true;
                }
            }
            if (principal.any) {
                return true;
            }
        }
        return false;
    }
    matchesEnvoyPermissions(permissions, test) {
        for (const permission of permissions) {
            if (permission.any) {
                return true;
            }
            if (permission.header?.name && permission.header?.exact_match) {
                return true;
            }
            if (permission.url_path?.path?.exact) {
                if (permission.url_path.path.exact === test.path) {
                    return true;
                }
            }
        }
        return false;
    }
    async getIstioPolicy(test) {
        try {
            const k8sApiEndpoint = this.config.options?.k8sApiEndpoint ||
                process.env.KUBERNETES_SERVICE_HOST ||
                'https://kubernetes.default.svc';
            const namespace = this.config.namespace || 'default';
            const token = this.config.credentials?.token ||
                process.env.KUBERNETES_SERVICE_ACCOUNT_TOKEN ||
                '';
            const response = await fetch(`${k8sApiEndpoint}/apis/security.istio.io/v1beta1/namespaces/${namespace}/authorizationpolicies`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
            });
            if (!response.ok) {
                return this.getIstioPolicyFromFile(test);
            }
            const data = await response.json();
            const items = data.items || [];
            for (const item of items) {
                const spec = item.spec || {};
                const selector = spec.selector || {};
                const matchLabels = selector.matchLabels || {};
                if (matchLabels.app === test.targetService ||
                    matchLabels.service === test.targetService ||
                    !Object.keys(matchLabels).length) {
                    return {
                        name: item.metadata.name,
                        namespace: item.metadata.namespace || namespace,
                        type: 'AuthorizationPolicy',
                        spec: spec,
                    };
                }
            }
            return null;
        }
        catch (error) {
            return this.getIstioPolicyFromFile(test);
        }
    }
    async getIstioPolicyFromFile(test) {
        try {
            const fs = require('fs/promises');
            const path = require('path');
            const policyPath = path.join(process.cwd(), 'policies', 'istio', `${test.targetService}-policy.yaml`);
            const content = await fs.readFile(policyPath, 'utf-8');
            const yaml = require('yaml');
            const policy = yaml.parse(content);
            return {
                name: policy.metadata?.name || 'policy',
                namespace: policy.metadata?.namespace || this.config.namespace || 'default',
                type: 'AuthorizationPolicy',
                spec: policy.spec || {},
            };
        }
        catch {
            return null;
        }
    }
    evaluateIstioPolicy(policy, test) {
        const spec = policy.spec || {};
        if (spec.action === 'DENY') {
            return false;
        }
        if (spec.rules) {
            for (const rule of spec.rules) {
                if (this.matchesIstioRule(rule, test)) {
                    return spec.action !== 'DENY';
                }
            }
        }
        return true;
    }
    matchesIstioRule(rule, test) {
        if (rule.from) {
            const sourceMatches = rule.from.some((from) => {
                if (from.source?.principals) {
                    return from.source.principals.includes(`cluster.local/ns/${this.config.namespace}/sa/${test.sourceService}`);
                }
                return true;
            });
            if (!sourceMatches)
                return false;
        }
        if (rule.to) {
            const destMatches = rule.to.some((to) => {
                if (to.operation?.hosts) {
                    return to.operation.hosts.includes(test.targetService);
                }
                if (to.operation?.paths) {
                    return to.operation.paths.includes(test.path);
                }
                if (to.operation?.methods) {
                    return to.operation.methods.includes(test.method);
                }
                return true;
            });
            if (!destMatches)
                return false;
        }
        return true;
    }
    async createIstioPolicy(policy) {
        try {
            const k8sApiEndpoint = this.config.options?.k8sApiEndpoint ||
                process.env.KUBERNETES_SERVICE_HOST ||
                'https://kubernetes.default.svc';
            const namespace = policy.namespace || this.config.namespace || 'default';
            const token = this.config.credentials?.token ||
                process.env.KUBERNETES_SERVICE_ACCOUNT_TOKEN ||
                '';
            const policyResource = {
                apiVersion: 'security.istio.io/v1beta1',
                kind: 'AuthorizationPolicy',
                metadata: {
                    name: policy.name,
                    namespace: namespace,
                },
                spec: policy.spec,
            };
            const response = await fetch(`${k8sApiEndpoint}/apis/security.istio.io/v1beta1/namespaces/${namespace}/authorizationpolicies`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(policyResource),
            });
            if (!response.ok) {
                const error = await response.text();
                throw new Error(`Failed to create Istio policy: ${response.statusText} - ${error}`);
            }
            const created = await response.json();
            return {
                name: created.metadata.name,
                namespace: created.metadata.namespace,
                type: 'AuthorizationPolicy',
                spec: created.spec,
            };
        }
        catch (error) {
            return await this.saveIstioPolicyToFile(policy);
        }
    }
    async saveIstioPolicyToFile(policy) {
        try {
            const fs = require('fs/promises');
            const path = require('path');
            const yaml = require('yaml');
            const policyDir = path.join(process.cwd(), 'policies', 'istio');
            await fs.mkdir(policyDir, { recursive: true });
            const policyResource = {
                apiVersion: 'security.istio.io/v1beta1',
                kind: 'AuthorizationPolicy',
                metadata: {
                    name: policy.name,
                    namespace: policy.namespace || 'default',
                },
                spec: policy.spec,
            };
            const yamlContent = yaml.stringify(policyResource);
            const filePath = path.join(policyDir, `${policy.name}.yaml`);
            await fs.writeFile(filePath, yamlContent);
            return policy;
        }
        catch (error) {
            throw new Error(`Failed to save Istio policy: ${error.message}`);
        }
    }
    async testMicroservicesAccess(services, user) {
        const results = [];
        for (let i = 0; i < services.length; i++) {
            for (let j = i + 1; j < services.length; j++) {
                const test = {
                    sourceService: services[i],
                    targetService: services[j],
                    path: '/api/v1',
                    method: 'GET',
                    expectedAllowed: true,
                };
                const result = await this.testServiceToServiceAccess(test);
                results.push(result);
            }
        }
        return results;
    }
    async validatePolicies(policies) {
        const errors = [];
        for (const policy of policies) {
            if (!policy.name) {
                errors.push(`Policy missing name`);
            }
            if (!policy.spec) {
                errors.push(`Policy ${policy.name} missing spec`);
            }
            if (policy.type === 'AuthorizationPolicy') {
                const specErrors = this.validateAuthorizationPolicy(policy);
                errors.push(...specErrors);
            }
        }
        return {
            valid: errors.length === 0,
            errors,
        };
    }
    validateAuthorizationPolicy(policy) {
        const errors = [];
        const spec = policy.spec || {};
        if (!spec.action) {
            errors.push(`Policy ${policy.name} missing action`);
        }
        else if (!['ALLOW', 'DENY'].includes(spec.action)) {
            errors.push(`Policy ${policy.name} has invalid action: ${spec.action}`);
        }
        return errors;
    }
    async getServiceMeshMetrics() {
        try {
            if (this.config.type === 'istio') {
                return await this.getIstioMetrics();
            }
            else if (this.config.type === 'envoy') {
                return await this.getEnvoyMetrics();
            }
        }
        catch (error) {
        }
        return {
            totalPolicies: 0,
            services: 0,
            requests: 0,
            deniedRequests: 0,
        };
    }
    async getIstioMetrics() {
        try {
            const k8sApiEndpoint = this.config.options?.k8sApiEndpoint ||
                process.env.KUBERNETES_SERVICE_HOST ||
                'https://kubernetes.default.svc';
            const namespace = this.config.namespace || 'default';
            const token = this.config.credentials?.token || '';
            const policyResponse = await fetch(`${k8sApiEndpoint}/apis/security.istio.io/v1beta1/namespaces/${namespace}/authorizationpolicies`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            let totalPolicies = 0;
            if (policyResponse.ok) {
                const data = await policyResponse.json();
                totalPolicies = data.items?.length || 0;
            }
            const serviceResponse = await fetch(`${k8sApiEndpoint}/api/v1/namespaces/${namespace}/services`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            let services = 0;
            if (serviceResponse.ok) {
                const data = await serviceResponse.json();
                services = data.items?.length || 0;
            }
            const prometheusEndpoint = this.config.options?.prometheusEndpoint ||
                'http://prometheus.istio-system:9090';
            let requests = 0;
            let deniedRequests = 0;
            try {
                const metricsResponse = await fetch(`${prometheusEndpoint}/api/v1/query?query=istio_requests_total{namespace="${namespace}"}`);
                if (metricsResponse.ok) {
                    const metricsData = await metricsResponse.json();
                    const result = metricsData.data?.result || [];
                    requests = result.reduce((sum, r) => sum + parseFloat(r.value[1] || 0), 0);
                    const deniedResponse = await fetch(`${prometheusEndpoint}/api/v1/query?query=istio_requests_total{namespace="${namespace}",response_code="403"}`);
                    if (deniedResponse.ok) {
                        const deniedData = await deniedResponse.json();
                        const deniedResult = deniedData.data?.result || [];
                        deniedRequests = deniedResult.reduce((sum, r) => sum + parseFloat(r.value[1] || 0), 0);
                    }
                }
            }
            catch {
            }
            return {
                totalPolicies,
                services,
                requests: Math.round(requests),
                deniedRequests: Math.round(deniedRequests),
            };
        }
        catch {
            return {
                totalPolicies: 0,
                services: 0,
                requests: 0,
                deniedRequests: 0,
            };
        }
    }
    async getEnvoyMetrics() {
        try {
            const envoyAdminPort = this.config.options?.envoyAdminPort || 15000;
            const statsResponse = await fetch(`http://localhost:${envoyAdminPort}/stats?format=json`);
            let requests = 0;
            let deniedRequests = 0;
            if (statsResponse.ok) {
                const stats = await statsResponse.json();
                const statsArray = stats.stats || [];
                for (const stat of statsArray) {
                    if (stat.name === 'http.incoming_rq_total') {
                        requests += parseInt(stat.value || 0);
                    }
                    if (stat.name === 'rbac.denied') {
                        deniedRequests += parseInt(stat.value || 0);
                    }
                }
            }
            return {
                totalPolicies: 0,
                services: 0,
                requests,
                deniedRequests,
            };
        }
        catch {
            return {
                totalPolicies: 0,
                services: 0,
                requests: 0,
                deniedRequests: 0,
            };
        }
    }
}
exports.ServiceMeshIntegration = ServiceMeshIntegration;
//# sourceMappingURL=service-mesh-integration.js.map