"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RealtimeIngestionService = void 0;
const events_1 = require("events");
class RealtimeIngestionService extends events_1.EventEmitter {
    constructor(normalizationEngine, riskScorer, config = {}) {
        super();
        this.processingQueue = [];
        this.isProcessing = false;
        this.normalizationEngine = normalizationEngine;
        this.riskScorer = riskScorer;
        this.config = {
            enableRealTimeNormalization: config.enableRealTimeNormalization !== false,
            enableRealTimeRiskScoring: config.enableRealTimeRiskScoring !== false,
            batchSize: config.batchSize || 10,
            batchTimeout: config.batchTimeout || 1000,
            maxConcurrency: config.maxConcurrency || 5,
        };
    }
    async processWebhook(payload) {
        return new Promise((resolve, reject) => {
            this.processingQueue.push({ payload, resolve, reject });
            this.emit('finding_received', {
                type: 'finding_received',
                timestamp: new Date(),
                rawPayload: payload,
                metadata: payload.metadata,
            });
            if (!this.isProcessing) {
                this.processQueue();
            }
        });
    }
    async processQueue() {
        if (this.processingQueue.length === 0) {
            this.isProcessing = false;
            return;
        }
        this.isProcessing = true;
        if (this.batchTimer) {
            clearTimeout(this.batchTimer);
            this.batchTimer = undefined;
        }
        const batch = [];
        const startTime = Date.now();
        while (batch.length < (this.config.batchSize || 10) &&
            this.processingQueue.length > 0 &&
            Date.now() - startTime < (this.config.batchTimeout || 1000)) {
            batch.push(this.processingQueue.shift());
        }
        try {
            const results = await Promise.allSettled(batch.map(item => this.processPayload(item.payload)));
            results.forEach((result, index) => {
                const item = batch[index];
                if (result.status === 'fulfilled') {
                    item.resolve(result.value);
                }
                else {
                    item.reject(result.reason);
                }
            });
        }
        catch (error) {
            batch.forEach(item => {
                item.reject(error);
            });
        }
        if (this.processingQueue.length > 0) {
            setImmediate(() => this.processQueue());
        }
        else {
            this.isProcessing = false;
        }
    }
    async processPayload(payload) {
        try {
            let findings = [];
            if (this.config.enableRealTimeNormalization) {
                findings = await this.normalizeFindings(payload);
            }
            else {
                findings = payload.findings.map((f, idx) => ({
                    id: `finding-${Date.now()}-${idx}`,
                    event: {
                        kind: 'event',
                        category: 'security',
                        type: 'vulnerability',
                        action: 'detected',
                        severity: 500,
                    },
                    source: this.mapScannerToSource(payload.scannerId),
                    scannerId: payload.scannerId,
                    scannerFindingId: f.id || `finding-${idx}`,
                    title: f.title || f.name || 'Security Finding',
                    description: f.description || '',
                    severity: this.mapSeverity(f.severity || 'medium'),
                    confidence: 'confirmed',
                    asset: {
                        type: 'application',
                        applicationId: payload.metadata?.applicationId,
                        component: f.component || '',
                    },
                    status: 'open',
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    riskScore: 50,
                    raw: f,
                }));
            }
            if (this.config.enableRealTimeRiskScoring) {
                findings = await this.scoreFindings(findings, payload.metadata);
            }
            findings.forEach(finding => {
                this.emit('finding_normalized', {
                    type: 'finding_normalized',
                    timestamp: new Date(),
                    finding,
                    metadata: payload.metadata,
                });
            });
            return findings;
        }
        catch (error) {
            this.emit('error', {
                type: 'error',
                timestamp: new Date(),
                error,
                rawPayload: payload,
            });
            throw error;
        }
    }
    async normalizeFindings(payload) {
        const normalized = [];
        for (const rawFinding of payload.findings) {
            try {
                const result = await this.normalizationEngine.normalize(payload.scannerId, rawFinding, payload.metadata);
                if (Array.isArray(result)) {
                    normalized.push(...result);
                }
                else {
                    normalized.push(result);
                }
            }
            catch (error) {
                console.error(`Failed to normalize finding from ${payload.scannerId}:`, error);
            }
        }
        return normalized;
    }
    async scoreFindings(findings, metadata) {
        const scored = [];
        for (const finding of findings) {
            try {
                const riskScore = await this.riskScorer.calculateRiskScore(finding, {
                    applicationId: finding.asset.applicationId || metadata?.applicationId,
                    applicationName: metadata?.applicationName,
                });
                finding.riskScore = riskScore.totalScore;
                finding.businessImpact = riskScore.businessImpact;
                this.emit('finding_scored', {
                    type: 'finding_scored',
                    timestamp: new Date(),
                    finding,
                    metadata,
                });
                scored.push(finding);
            }
            catch (error) {
                console.error('Failed to score finding:', error);
                scored.push(finding);
            }
        }
        return scored;
    }
    mapScannerToSource(scannerId) {
        const sourceMap = {
            'sonarqube': 'sast',
            'snyk': 'sca',
            'snyk-container': 'container',
            'owasp-zap': 'dast',
            'checkov': 'iac',
            'trivy': 'container',
            'clair': 'container',
            'sonatype-iq': 'sca',
            'aws-security-hub': 'cspm',
        };
        return sourceMap[scannerId.toLowerCase()] || 'security';
    }
    mapSeverity(severity) {
        if (typeof severity === 'number') {
            if (severity >= 9)
                return 'critical';
            if (severity >= 7)
                return 'high';
            if (severity >= 4)
                return 'medium';
            if (severity > 0)
                return 'low';
            return 'info';
        }
        const severityStr = severity.toLowerCase();
        if (severityStr.includes('critical') || severityStr.includes('critical'))
            return 'critical';
        if (severityStr.includes('high') || severityStr.includes('severe'))
            return 'high';
        if (severityStr.includes('medium') || severityStr.includes('moderate'))
            return 'medium';
        if (severityStr.includes('low') || severityStr.includes('negligible'))
            return 'low';
        return 'info';
    }
    getStats() {
        return {
            queueLength: this.processingQueue.length,
            isProcessing: this.isProcessing,
            config: this.config,
        };
    }
    stop() {
        this.processingQueue.forEach(item => {
            item.reject(new Error('Ingestion service stopped'));
        });
        this.processingQueue = [];
        this.isProcessing = false;
        if (this.batchTimer) {
            clearTimeout(this.batchTimer);
            this.batchTimer = undefined;
        }
    }
}
exports.RealtimeIngestionService = RealtimeIngestionService;
//# sourceMappingURL=realtime-ingestion.js.map