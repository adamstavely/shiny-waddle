"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseScannerAdapter = void 0;
class BaseScannerAdapter {
    constructor(config) {
        this.config = config;
    }
    extractVulnerabilityInfo(finding) {
        return {};
    }
    extractFileLocation(finding) {
        return {};
    }
    extractRemediation(finding) {
        return {
            description: '',
            steps: [],
            references: [],
        };
    }
    generateFindingId(scannerFindingId) {
        return `${this.config.scannerId}-${scannerFindingId}-${Date.now()}`;
    }
    calculateRiskScore(severity, exploitability, assetCriticality) {
        const severityScores = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25,
            'info': 10,
        };
        const exploitabilityScores = {
            'exploitable': 1.0,
            'potentially-exploitable': 0.7,
            'not-exploitable': 0.3,
        };
        const criticalityScores = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
        };
        let score = severityScores[severity.toLowerCase()] || 50;
        if (exploitability) {
            score *= exploitabilityScores[exploitability] || 0.5;
        }
        if (assetCriticality) {
            score *= criticalityScores[assetCriticality.toLowerCase()] || 0.6;
        }
        return Math.round(score);
    }
    batchNormalize(findings, metadata) {
        const normalized = [];
        for (const finding of findings) {
            if (!this.validate(finding))
                continue;
            const result = this.normalize(finding, metadata);
            if (Array.isArray(result)) {
                normalized.push(...result);
            }
            else {
                normalized.push(result);
            }
        }
        return normalized;
    }
}
exports.BaseScannerAdapter = BaseScannerAdapter;
//# sourceMappingURL=base-adapter.js.map