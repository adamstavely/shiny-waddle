/**
 * Alerting Engine
 * 
 * Configurable alert rules, multi-channel alerts, aggregation, and fatigue prevention
 */

import { UnifiedFinding } from '../core/unified-finding-schema';
import { EventEmitter } from 'events';

export interface AlertRule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  conditions: AlertCondition[];
  channels: string[]; // Channel IDs
  severity?: 'critical' | 'high' | 'medium' | 'low';
  aggregation?: {
    enabled: boolean;
    window: number; // milliseconds
    maxAlerts?: number;
  };
  cooldown?: number; // milliseconds - prevent alert fatigue
  lastTriggered?: Date;
  metadata?: Record<string, any>;
}

export interface AlertCondition {
  field: string; // e.g., 'severity', 'riskScore', 'vulnerability.id'
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

export class AlertingEngine extends EventEmitter {
  private rules: Map<string, AlertRule> = new Map();
  private channels: Map<string, AlertChannel> = new Map();
  private alerts: Map<string, Alert> = new Map();
  private aggregatedAlerts: Map<string, AggregatedAlert> = new Map();
  private alertHistory: Alert[] = [];
  private cooldownTimers: Map<string, NodeJS.Timeout> = new Map();
  private aggregationWindows: Map<string, {
    findings: UnifiedFinding[];
    timer?: NodeJS.Timeout;
    alertCount: number;
  }> = new Map();

  /**
   * Register alert rule
   */
  registerRule(rule: AlertRule): void {
    this.rules.set(rule.id, rule);
    this.emit('rule_registered', rule);
  }

  /**
   * Remove alert rule
   */
  removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
    // Clear aggregation window
    this.aggregationWindows.delete(ruleId);
    // Clear cooldown timer
    if (this.cooldownTimers.has(ruleId)) {
      clearTimeout(this.cooldownTimers.get(ruleId)!);
      this.cooldownTimers.delete(ruleId);
    }
    this.emit('rule_removed', ruleId);
  }

  /**
   * Register alert channel
   */
  registerChannel(channel: AlertChannel): void {
    this.channels.set(channel.id, channel);
    this.emit('channel_registered', channel);
  }

  /**
   * Remove alert channel
   */
  removeChannel(channelId: string): void {
    this.channels.delete(channelId);
    this.emit('channel_removed', channelId);
  }

  /**
   * Evaluate finding against all rules
   */
  async evaluateFinding(finding: UnifiedFinding): Promise<Alert[]> {
    const triggeredAlerts: Alert[] = [];

    for (const [ruleId, rule] of this.rules) {
      if (!rule.enabled) continue;

      // Check cooldown
      if (this.isInCooldown(rule)) {
        continue;
      }

      // Evaluate conditions
      if (this.evaluateConditions(rule.conditions, finding)) {
        const alert = await this.createAlert(rule, finding);
        triggeredAlerts.push(alert);

        // Update cooldown
        rule.lastTriggered = new Date();
        this.setCooldown(rule);

        // Handle aggregation
        if (rule.aggregation?.enabled) {
          await this.handleAggregation(rule, finding, alert);
        } else {
          // Send immediately
          await this.sendAlert(alert);
        }
      }
    }

    return triggeredAlerts;
  }

  /**
   * Evaluate multiple findings
   */
  async evaluateFindings(findings: UnifiedFinding[]): Promise<Alert[]> {
    const allAlerts: Alert[] = [];

    for (const finding of findings) {
      const alerts = await this.evaluateFinding(finding);
      allAlerts.push(...alerts);
    }

    return allAlerts;
  }

  /**
   * Evaluate alert conditions
   */
  private evaluateConditions(conditions: AlertCondition[], finding: any): boolean {
    if (conditions.length === 0) return false;

    let result = this.evaluateCondition(conditions[0], finding);

    for (let i = 1; i < conditions.length; i++) {
      const condition = conditions[i];
      const conditionResult = this.evaluateCondition(condition, finding);
      const operator = condition.logicalOperator || 'AND';

      if (operator === 'AND') {
        result = result && conditionResult;
      } else {
        result = result || conditionResult;
      }
    }

    return result;
  }

  /**
   * Evaluate single condition
   */
  private evaluateCondition(condition: AlertCondition, finding: any): boolean {
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

  /**
   * Get field value from finding using dot notation
   */
  private getFieldValue(obj: any, field: string): any {
    const parts = field.split('.');
    let value: any = obj;
    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = value[part];
      } else {
        return undefined;
      }
    }
    return value;
  }

  /**
   * Create alert from rule and finding
   */
  private async createAlert(rule: AlertRule, finding: UnifiedFinding): Promise<Alert> {
    const alert: Alert = {
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

  /**
   * Generate alert message
   */
  private generateAlertMessage(rule: AlertRule, finding: UnifiedFinding): string {
    const parts: string[] = [];
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

  /**
   * Handle alert aggregation
   */
  private async handleAggregation(
    rule: AlertRule,
    finding: UnifiedFinding,
    alert: Alert
  ): Promise<void> {
    const window = this.aggregationWindows.get(rule.id) || {
      findings: [],
      alertCount: 0,
    };

    window.findings.push(finding);
    window.alertCount++;

    // Check if we should send aggregated alert
    const shouldSend =
      rule.aggregation?.maxAlerts &&
      window.alertCount >= rule.aggregation.maxAlerts;

    if (shouldSend) {
      await this.sendAggregatedAlert(rule, window.findings);
      this.aggregationWindows.delete(rule.id);
      if (window.timer) {
        clearTimeout(window.timer);
      }
    } else {
      // Set timer to send after window expires
      if (!window.timer) {
        window.timer = setTimeout(async () => {
          await this.sendAggregatedAlert(rule, window.findings);
          this.aggregationWindows.delete(rule.id);
        }, rule.aggregation!.window);
      }
      this.aggregationWindows.set(rule.id, window);
    }
  }

  /**
   * Send aggregated alert
   */
  private async sendAggregatedAlert(
    rule: AlertRule,
    findings: UnifiedFinding[]
  ): Promise<void> {
    const aggregated: AggregatedAlert = {
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

  /**
   * Send alert to channels
   */
  private async sendAlert(alert: Alert): Promise<void> {
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
    } catch (error: any) {
      alert.status = 'failed';
      this.emit('alert_failed', { alert, error });
    }
  }

  /**
   * Send aggregated alert to channels
   */
  private async sendAggregatedAlertToChannels(alert: AggregatedAlert): Promise<void> {
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
    } catch (error: any) {
      alert.status = 'failed';
      this.emit('aggregated_alert_failed', { alert, error });
    }
  }

  /**
   * Send alert to specific channel
   */
  private async sendToChannel(channel: AlertChannel, alert: Alert): Promise<void> {
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

  /**
   * Send aggregated alert to specific channel
   */
  private async sendAggregatedToChannel(
    channel: AlertChannel,
    alert: AggregatedAlert
  ): Promise<void> {
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

  // Channel-specific senders (implementations would use actual APIs)

  private async sendEmail(channel: AlertChannel, alert: Alert): Promise<void> {
    // In a real implementation, this would use an email service
    console.log(`[Email] Sending alert to ${channel.config.recipients}: ${alert.title}`);
    this.emit('channel_sent', { channel, alert, type: 'email' });
  }

  private async sendSlack(channel: AlertChannel, alert: Alert): Promise<void> {
    // In a real implementation, this would use Slack API
    console.log(`[Slack] Sending alert to ${channel.config.webhookUrl}: ${alert.title}`);
    this.emit('channel_sent', { channel, alert, type: 'slack' });
  }

  private async sendPagerDuty(channel: AlertChannel, alert: Alert): Promise<void> {
    // In a real implementation, this would use PagerDuty API
    console.log(`[PagerDuty] Sending alert: ${alert.title}`);
    this.emit('channel_sent', { channel, alert, type: 'pagerduty' });
  }

  private async sendWebhook(channel: AlertChannel, alert: Alert): Promise<void> {
    // In a real implementation, this would POST to webhook URL
    console.log(`[Webhook] Sending alert to ${channel.config.url}: ${alert.title}`);
    this.emit('channel_sent', { channel, alert, type: 'webhook' });
  }

  private async sendTeams(channel: AlertChannel, alert: Alert): Promise<void> {
    // In a real implementation, this would use Microsoft Teams API
    console.log(`[Teams] Sending alert: ${alert.title}`);
    this.emit('channel_sent', { channel, alert, type: 'teams' });
  }

  private async sendAggregatedEmail(
    channel: AlertChannel,
    alert: AggregatedAlert
  ): Promise<void> {
    console.log(
      `[Email] Sending aggregated alert to ${channel.config.recipients}: ${alert.title} (${alert.findingCount} findings)`
    );
    this.emit('aggregated_channel_sent', { channel, alert, type: 'email' });
  }

  private async sendAggregatedSlack(
    channel: AlertChannel,
    alert: AggregatedAlert
  ): Promise<void> {
    console.log(
      `[Slack] Sending aggregated alert: ${alert.title} (${alert.findingCount} findings)`
    );
    this.emit('aggregated_channel_sent', { channel, alert, type: 'slack' });
  }

  private async sendAggregatedPagerDuty(
    channel: AlertChannel,
    alert: AggregatedAlert
  ): Promise<void> {
    console.log(`[PagerDuty] Sending aggregated alert: ${alert.title}`);
    this.emit('aggregated_channel_sent', { channel, alert, type: 'pagerduty' });
  }

  private async sendAggregatedWebhook(
    channel: AlertChannel,
    alert: AggregatedAlert
  ): Promise<void> {
    console.log(`[Webhook] Sending aggregated alert: ${alert.title}`);
    this.emit('aggregated_channel_sent', { channel, alert, type: 'webhook' });
  }

  private async sendAggregatedTeams(
    channel: AlertChannel,
    alert: AggregatedAlert
  ): Promise<void> {
    console.log(`[Teams] Sending aggregated alert: ${alert.title}`);
    this.emit('aggregated_channel_sent', { channel, alert, type: 'teams' });
  }

  /**
   * Check if rule is in cooldown period
   */
  private isInCooldown(rule: AlertRule): boolean {
    if (!rule.cooldown || !rule.lastTriggered) {
      return false;
    }
    const timeSinceLastTrigger = Date.now() - rule.lastTriggered.getTime();
    return timeSinceLastTrigger < rule.cooldown;
  }

  /**
   * Set cooldown timer for rule
   */
  private setCooldown(rule: AlertRule): void {
    if (!rule.cooldown) return;

    // Clear existing timer
    if (this.cooldownTimers.has(rule.id)) {
      clearTimeout(this.cooldownTimers.get(rule.id)!);
    }

    // Set new timer
    const timer = setTimeout(() => {
      this.cooldownTimers.delete(rule.id);
    }, rule.cooldown);

    this.cooldownTimers.set(rule.id, timer);
  }

  /**
   * Get alert statistics
   */
  getStats(): {
    ruleCount: number;
    channelCount: number;
    alertCount: number;
    aggregatedAlertCount: number;
    historySize: number;
  } {
    return {
      ruleCount: this.rules.size,
      channelCount: this.channels.size,
      alertCount: this.alerts.size,
      aggregatedAlertCount: this.aggregatedAlerts.size,
      historySize: this.alertHistory.length,
    };
  }
}

