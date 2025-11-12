"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultiCloudIntegration = void 0;
const aws_security_hub_adapter_1 = require("./scanner-adapters/aws-security-hub-adapter");
const azure_security_center_adapter_1 = require("./scanner-adapters/azure-security-center-adapter");
const gcp_security_command_center_adapter_1 = require("./scanner-adapters/gcp-security-command-center-adapter");
class MultiCloudIntegration {
    constructor() {
        this.adapters = new Map();
        this.configs = new Map();
    }
    registerProvider(config) {
        this.configs.set(config.provider, config);
        if (config.enabled) {
            let adapter;
            switch (config.provider) {
                case 'aws':
                    adapter = new aws_security_hub_adapter_1.AWSSecurityHubAdapter(config.config);
                    break;
                case 'azure':
                    adapter = new azure_security_center_adapter_1.AzureSecurityCenterAdapter(config.config);
                    break;
                case 'gcp':
                    adapter = new gcp_security_command_center_adapter_1.GCPSecurityCommandCenterAdapter(config.config);
                    break;
                default:
                    throw new Error(`Unsupported cloud provider: ${config.provider}`);
            }
            this.adapters.set(config.provider, adapter);
        }
    }
    async normalizeProviderFindings(provider, rawFindings) {
        const adapter = this.adapters.get(provider);
        if (!adapter) {
            throw new Error(`Provider ${provider} not registered or not enabled`);
        }
        const normalized = [];
        for (const rawFinding of rawFindings) {
            try {
                if (adapter.validate(rawFinding)) {
                    const normalizedFinding = adapter.normalize(rawFinding);
                    if (Array.isArray(normalizedFinding)) {
                        normalized.push(...normalizedFinding);
                    }
                    else {
                        normalized.push(normalizedFinding);
                    }
                }
            }
            catch (error) {
                console.error(`Failed to normalize finding from ${provider}:`, error.message);
            }
        }
        return normalized;
    }
    async aggregateFindings(providerFindings) {
        const aggregated = [];
        for (const [provider, rawFindings] of providerFindings.entries()) {
            const normalized = await this.normalizeProviderFindings(provider, rawFindings);
            for (const finding of normalized) {
                const multiCloudFinding = {
                    finding,
                    provider,
                    region: this.extractRegion(finding, provider),
                    resourceId: finding.asset?.component || finding.id,
                    accountId: provider === 'aws' ? this.extractAccountId(finding) : undefined,
                    subscriptionId: provider === 'azure' ? this.extractSubscriptionId(finding) : undefined,
                    projectId: provider === 'gcp' ? this.extractProjectId(finding) : undefined,
                };
                aggregated.push(multiCloudFinding);
            }
        }
        return aggregated;
    }
    async getProviderSummaries(findings) {
        const summaries = new Map();
        const providers = ['aws', 'azure', 'gcp'];
        for (const provider of providers) {
            const providerFindings = findings.filter(f => f.provider === provider);
            const findingsBySeverity = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            };
            const findingsByRegion = {};
            let totalRiskScore = 0;
            for (const multiCloudFinding of providerFindings) {
                const severity = multiCloudFinding.finding.severity;
                findingsBySeverity[severity] = (findingsBySeverity[severity] || 0) + 1;
                const region = multiCloudFinding.region || 'unknown';
                findingsByRegion[region] = (findingsByRegion[region] || 0) + 1;
                totalRiskScore += multiCloudFinding.finding.riskScore || 0;
            }
            const avgRiskScore = providerFindings.length > 0
                ? totalRiskScore / providerFindings.length
                : 0;
            summaries.set(provider, {
                provider,
                totalFindings: providerFindings.length,
                findingsBySeverity,
                findingsByRegion,
                riskScore: Math.round(avgRiskScore),
                lastScanTime: providerFindings.length > 0
                    ? new Date(Math.max(...providerFindings.map(f => new Date(f.finding.createdAt).getTime())))
                    : undefined,
            });
        }
        return summaries;
    }
    findCrossCloudDuplicates(findings) {
        const duplicates = new Map();
        const groups = new Map();
        for (const finding of findings) {
            const key = this.generateDuplicateKey(finding);
            if (!groups.has(key)) {
                groups.set(key, []);
            }
            groups.get(key).push(finding);
        }
        for (const [key, group] of groups.entries()) {
            if (group.length > 1) {
                const providers = new Set(group.map(f => f.provider));
                if (providers.size > 1) {
                    duplicates.set(key, group);
                }
            }
        }
        return duplicates;
    }
    getFindingsByProvider(findings) {
        const byProvider = new Map();
        for (const finding of findings) {
            if (!byProvider.has(finding.provider)) {
                byProvider.set(finding.provider, []);
            }
            byProvider.get(finding.provider).push(finding);
        }
        return byProvider;
    }
    getFindingsByRegion(findings) {
        const byRegion = new Map();
        for (const finding of findings) {
            const region = finding.region || 'unknown';
            if (!byRegion.has(region)) {
                byRegion.set(region, []);
            }
            byRegion.get(region).push(finding);
        }
        return byRegion;
    }
    extractRegion(finding, provider) {
        const location = finding.asset?.location;
        if (location?.region) {
            return location.region;
        }
        const resourceId = finding.asset?.component || '';
        if (provider === 'aws') {
            const match = resourceId.match(/arn:aws:[^:]+:([^:]+):/);
            if (match)
                return match[1];
        }
        else if (provider === 'azure') {
            const match = resourceId.match(/\/locations\/([^\/]+)/);
            if (match)
                return match[1];
        }
        else if (provider === 'gcp') {
            const match = resourceId.match(/\/locations\/([^\/]+)/);
            if (match)
                return match[1];
        }
        return 'unknown';
    }
    extractAccountId(finding) {
        const resourceId = finding.asset?.component || '';
        const match = resourceId.match(/arn:aws:[^:]+:[^:]+:(\d+):/);
        return match ? match[1] : undefined;
    }
    extractSubscriptionId(finding) {
        const resourceId = finding.asset?.component || '';
        const match = resourceId.match(/\/subscriptions\/([^\/]+)/);
        return match ? match[1] : undefined;
    }
    extractProjectId(finding) {
        const resourceId = finding.asset?.component || '';
        const match = resourceId.match(/\/projects\/([^\/]+)/);
        return match ? match[1] : undefined;
    }
    generateDuplicateKey(finding) {
        const f = finding.finding;
        const parts = [
            f.title,
            f.severity,
            f.asset?.component,
            f.vulnerability?.cve?.id,
            f.vulnerability?.classification,
        ].filter(Boolean);
        return parts.join('|');
    }
}
exports.MultiCloudIntegration = MultiCloudIntegration;
//# sourceMappingURL=multi-cloud-integration.js.map