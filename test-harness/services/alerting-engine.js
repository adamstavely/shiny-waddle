"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlertingEngine = void 0;
const events_1 = require("events");
class AlertingEngine extends events_1.EventEmitter {
    constructor() {
        super(...arguments);
        this.rules = new Map();
        this.channels = new Map();
        this.alerts = new Map();
        this.aggregatedAlerts = new Map();
        this.alertHistory = [];
        this.cooldownTimers = new Map();
        this.aggregationWindows = new Map();
    }
    registerRule(rule) {
        this.rules.set(rule.id, rule);
        this.emit('rule_registered', rule);
    }
    removeRule(ruleId) {
        this.rules.delete(ruleId);
        this.aggregationWindows.delete(ruleId);
        if (this.cooldownTimers.has(ruleId)) {
            clearTimeout(this.cooldownTimers.get(ruleId));
            this.cooldownTimers.delete(ruleId);
        }
        this.emit('rule_removed', ruleId);
    }
    registerChannel(channel) {
        this.channels.set(channel.id, channel);
        this.emit('channel_registered', channel);
    }
    removeChannel(channelId) {
        this.channels.delete(channelId);
        this.emit('channel_removed', channelId);
    }
    async evaluateFinding(finding) {
        const triggeredAlerts = [];
        for (const [ruleId, rule] of this.rules) {
            if (!rule.enabled)
                continue;
            if (this.isInCooldown(rule)) {
                continue;
            }
            if (this.evaluateConditions(rule.conditions, finding)) {
                const alert = await this.createAlert(rule, finding);
                triggeredAlerts.push(alert);
                rule.lastTriggered = new Date();
                this.setCooldown(rule);
                if (rule.aggregation?.enabled) {
                    await this.handleAggregation(rule, finding, alert);
                }
                else {
                    await this.sendAlert(alert);
                }
            }
        }
        return triggeredAlerts;
    }
    async evaluateFindings(findings) {
        const allAlerts = [];
        for (const finding of findings) {
            const alerts = await this.evaluateFinding(finding);
            allAlerts.push(...alerts);
        }
        return allAlerts;
    }
    evaluateConditions(conditions, finding) {
        if (conditions.length === 0)
            return false;
        let result = this.evaluateCondition(conditions[0], finding);
        for (let i = 1; i < conditions.length; i++) {
            const condition = conditions[i];
            const conditionResult = this.evaluateCondition(condition, finding);
            const operator = condition.logicalOperator || 'AND';
            if (operator === 'AND') {
                result = result && conditionResult;
            }
            else {
                result = result || conditionResult;
            }
        }
        return result;
    }
    evaluateCondition(condition, finding) {
        const fieldValue = this.getFieldValue(finding, condition.field);
        const conditionValue = condition.value;
        switch (condition.operator) {
            case 'equals':
                return fieldValue === conditionValue;
            case 'notEquals':
                return fieldValue !== conditionValue;
            case 'greaterThan':
                return Number(fieldValue) > Number(conditionValue);
            case 'lessThan':
                return Number(fieldValue) < Number(conditionValue);
            case 'contains':
                return String(fieldValue).includes(String(conditionValue));
            case 'matches':
                return new RegExp(String(conditionValue)).test(String(fieldValue));
            case 'in':
                return Array.isArray(conditionValue) && conditionValue.includes(fieldValue);
            default:
                return false;
        }
    }
    getFieldValue(obj, field) {
        const parts = field.split('.');
        let value = obj;
        for (const part of parts) {
            if (value && typeof value === 'object') {
                value = value[part];
            }
            else {
                return undefined;
            }
        }
        return value;
    }
    async createAlert(rule, finding) {
        const alert = {
            id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity || finding.severity,
            title: `${rule.name}: ${finding.title}`,
            message: this.generateAlertMessage(rule, finding),
            findings: [finding],
            triggeredAt: new Date(),
            channels: rule.channels,
            status: 'pending',
            metadata: {
                ...rule.metadata,
                findingId: finding.id,
            },
        };
        this.alerts.set(alert.id, alert);
        this.alertHistory.push(alert);
        this.emit('alert_created', alert);
        return alert;
    }
    generateAlertMessage(rule, finding) {
        const parts = [];
        parts.push(`Alert: ${rule.name}`);
        parts.push(`Finding: ${finding.title}`);
        parts.push(`Severity: ${finding.severity}`);
        parts.push(`Risk Score: ${finding.riskScore}`);
        if (finding.asset.applicationId) {
            parts.push(`Application: ${finding.asset.applicationId}`);
        }
        if (finding.vulnerability?.id) {
            parts.push(`Vulnerability: ${finding.vulnerability.id}`);
        }
        return parts.join('\n');
    }
    async handleAggregation(rule, finding, alert) {
        const window = this.aggregationWindows.get(rule.id) || {
            findings: [],
            alertCount: 0,
        };
        window.findings.push(finding);
        window.alertCount++;
        const shouldSend = rule.aggregation?.maxAlerts &&
            window.alertCount >= rule.aggregation.maxAlerts;
        if (shouldSend) {
            await this.sendAggregatedAlert(rule, window.findings);
            this.aggregationWindows.delete(rule.id);
            if (window.timer) {
                clearTimeout(window.timer);
            }
        }
        else {
            if (!window.timer) {
                window.timer = setTimeout(async () => {
                    await this.sendAggregatedAlert(rule, window.findings);
                    this.aggregationWindows.delete(rule.id);
                }, rule.aggregation.window);
            }
            this.aggregationWindows.set(rule.id, window);
        }
    }
    async sendAggregatedAlert(rule, findings) {
        const aggregated = {
            id: `agg-alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity || findings[0]?.severity || 'medium',
            title: `${rule.name} - ${findings.length} findings`,
            message: `Aggregated alert: ${findings.length} findings matched rule "${rule.name}"`,
            findingCount: findings.length,
            findings,
            triggeredAt: new Date(),
            channels: rule.channels,
            status: 'pending',
        };
        this.aggregatedAlerts.set(aggregated.id, aggregated);
        await this.sendAggregatedAlertToChannels(aggregated);
    }
    async sendAlert(alert) {
        alert.status = 'pending';
        this.emit('alert_sending', alert);
        try {
            for (const channelId of alert.channels) {
                const channel = this.channels.get(channelId);
                if (!channel || !channel.enabled) {
                    continue;
                }
                await this.sendToChannel(channel, alert);
            }
            alert.status = 'sent';
            this.emit('alert_sent', alert);
        }
        catch (error) {
            alert.status = 'failed';
            this.emit('alert_failed', { alert, error });
        }
    }
    async sendAggregatedAlertToChannels(alert) {
        alert.status = 'pending';
        this.emit('aggregated_alert_sending', alert);
        try {
            for (const channelId of alert.channels) {
                const channel = this.channels.get(channelId);
                if (!channel || !channel.enabled) {
                    continue;
                }
                await this.sendAggregatedToChannel(channel, alert);
            }
            alert.status = 'sent';
            this.emit('aggregated_alert_sent', alert);
        }
        catch (error) {
            alert.status = 'failed';
            this.emit('aggregated_alert_failed', { alert, error });
        }
    }
    async sendToChannel(channel, alert) {
        switch (channel.type) {
            case 'email':
                await this.sendEmail(channel, alert);
                break;
            case 'slack':
                await this.sendSlack(channel, alert);
                break;
            case 'pagerduty':
                await this.sendPagerDuty(channel, alert);
                break;
            case 'webhook':
                await this.sendWebhook(channel, alert);
                break;
            case 'teams':
                await this.sendTeams(channel, alert);
                break;
            default:
                console.warn(`Unknown channel type: ${channel.type}`);
        }
    }
    async sendAggregatedToChannel(channel, alert) {
        switch (channel.type) {
            case 'email':
                await this.sendAggregatedEmail(channel, alert);
                break;
            case 'slack':
                await this.sendAggregatedSlack(channel, alert);
                break;
            case 'pagerduty':
                await this.sendAggregatedPagerDuty(channel, alert);
                break;
            case 'webhook':
                await this.sendAggregatedWebhook(channel, alert);
                break;
            case 'teams':
                await this.sendAggregatedTeams(channel, alert);
                break;
            default:
                console.warn(`Unknown channel type: ${channel.type}`);
        }
    }
    async sendEmail(channel, alert) {
        console.log(`[Email] Sending alert to ${channel.config.recipients}: ${alert.title}`);
        this.emit('channel_sent', { channel, alert, type: 'email' });
    }
    async sendSlack(channel, alert) {
        console.log(`[Slack] Sending alert to ${channel.config.webhookUrl}: ${alert.title}`);
        this.emit('channel_sent', { channel, alert, type: 'slack' });
    }
    async sendPagerDuty(channel, alert) {
        console.log(`[PagerDuty] Sending alert: ${alert.title}`);
        this.emit('channel_sent', { channel, alert, type: 'pagerduty' });
    }
    async sendWebhook(channel, alert) {
        console.log(`[Webhook] Sending alert to ${channel.config.url}: ${alert.title}`);
        this.emit('channel_sent', { channel, alert, type: 'webhook' });
    }
    async sendTeams(channel, alert) {
        console.log(`[Teams] Sending alert: ${alert.title}`);
        this.emit('channel_sent', { channel, alert, type: 'teams' });
    }
    async sendAggregatedEmail(channel, alert) {
        console.log(`[Email] Sending aggregated alert to ${channel.config.recipients}: ${alert.title} (${alert.findingCount} findings)`);
        this.emit('aggregated_channel_sent', { channel, alert, type: 'email' });
    }
    async sendAggregatedSlack(channel, alert) {
        console.log(`[Slack] Sending aggregated alert: ${alert.title} (${alert.findingCount} findings)`);
        this.emit('aggregated_channel_sent', { channel, alert, type: 'slack' });
    }
    async sendAggregatedPagerDuty(channel, alert) {
        console.log(`[PagerDuty] Sending aggregated alert: ${alert.title}`);
        this.emit('aggregated_channel_sent', { channel, alert, type: 'pagerduty' });
    }
    async sendAggregatedWebhook(channel, alert) {
        console.log(`[Webhook] Sending aggregated alert: ${alert.title}`);
        this.emit('aggregated_channel_sent', { channel, alert, type: 'webhook' });
    }
    async sendAggregatedTeams(channel, alert) {
        console.log(`[Teams] Sending aggregated alert: ${alert.title}`);
        this.emit('aggregated_channel_sent', { channel, alert, type: 'teams' });
    }
    isInCooldown(rule) {
        if (!rule.cooldown || !rule.lastTriggered) {
            return false;
        }
        const timeSinceLastTrigger = Date.now() - rule.lastTriggered.getTime();
        return timeSinceLastTrigger < rule.cooldown;
    }
    setCooldown(rule) {
        if (!rule.cooldown)
            return;
        if (this.cooldownTimers.has(rule.id)) {
            clearTimeout(this.cooldownTimers.get(rule.id));
        }
        const timer = setTimeout(() => {
            this.cooldownTimers.delete(rule.id);
        }, rule.cooldown);
        this.cooldownTimers.set(rule.id, timer);
    }
    getStats() {
        return {
            ruleCount: this.rules.size,
            channelCount: this.channels.size,
            alertCount: this.alerts.size,
            aggregatedAlertCount: this.aggregatedAlerts.size,
            historySize: this.alertHistory.length,
        };
    }
}
exports.AlertingEngine = AlertingEngine;
//# sourceMappingURL=alerting-engine.js.map