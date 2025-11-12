import { UnifiedFinding } from '../core/unified-finding-schema';
import { EventEmitter } from 'events';
export interface AlertRule {
    id: string;
    name: string;
    description?: string;
    enabled: boolean;
    conditions: AlertCondition[];
    channels: string[];
    severity?: 'critical' | 'high' | 'medium' | 'low';
    aggregation?: {
        enabled: boolean;
        window: number;
        maxAlerts?: number;
    };
    cooldown?: number;
    lastTriggered?: Date;
    metadata?: Record<string, any>;
}
export interface AlertCondition {
    field: string;
    operator: 'equals' | 'notEquals' | 'greaterThan' | 'lessThan' | 'contains' | 'matches' | 'in';
    value: any;
    logicalOperator?: 'AND' | 'OR';
}
export interface Alert {
    id: string;
    ruleId: string;
    ruleName: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    message: string;
    findings: UnifiedFinding[];
    triggeredAt: Date;
    channels: string[];
    status: 'pending' | 'sent' | 'failed' | 'suppressed';
    metadata?: Record<string, any>;
}
export interface AlertChannel {
    id: string;
    type: 'email' | 'slack' | 'pagerduty' | 'webhook' | 'teams' | 'custom';
    name: string;
    enabled: boolean;
    config: Record<string, any>;
    metadata?: Record<string, any>;
}
export interface AggregatedAlert {
    id: string;
    ruleId: string;
    ruleName: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    message: string;
    findingCount: number;
    findings: UnifiedFinding[];
    triggeredAt: Date;
    channels: string[];
    status: 'pending' | 'sent' | 'failed';
}
export declare class AlertingEngine extends EventEmitter {
    private rules;
    private channels;
    private alerts;
    private aggregatedAlerts;
    private alertHistory;
    private cooldownTimers;
    private aggregationWindows;
    registerRule(rule: AlertRule): void;
    removeRule(ruleId: string): void;
    registerChannel(channel: AlertChannel): void;
    removeChannel(channelId: string): void;
    evaluateFinding(finding: UnifiedFinding): Promise<Alert[]>;
    evaluateFindings(findings: UnifiedFinding[]): Promise<Alert[]>;
    private evaluateConditions;
    private evaluateCondition;
    private getFieldValue;
    private createAlert;
    private generateAlertMessage;
    private handleAggregation;
    private sendAggregatedAlert;
    private sendAlert;
    private sendAggregatedAlertToChannels;
    private sendToChannel;
    private sendAggregatedToChannel;
    private sendEmail;
    private sendSlack;
    private sendPagerDuty;
    private sendWebhook;
    private sendTeams;
    private sendAggregatedEmail;
    private sendAggregatedSlack;
    private sendAggregatedPagerDuty;
    private sendAggregatedWebhook;
    private sendAggregatedTeams;
    private isInCooldown;
    private setCooldown;
    getStats(): {
        ruleCount: number;
        channelCount: number;
        alertCount: number;
        aggregatedAlertCount: number;
        historySize: number;
    };
}
