import { Injectable, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { AlertingEngine, AlertRule, AlertChannel, Alert } from '../../../heimdall-framework/services/alerting-engine';
import { UnifiedFinding } from '../../../heimdall-framework/core/unified-finding-schema';
import { AlertRuleEntity } from './entities/alert-rule.entity';
import { AlertChannelEntity } from './entities/alert-channel.entity';
import { AlertEntity } from './entities/alert.entity';
import { CreateAlertRuleDto } from './dto/create-alert-rule.dto';
import { UpdateAlertRuleDto } from './dto/update-alert-rule.dto';
import { CreateAlertChannelDto } from './dto/create-alert-channel.dto';
import { UpdateAlertChannelDto } from './dto/update-alert-channel.dto';
import { AlertQueryDto } from './dto/alert-query.dto';
import { NotificationsService } from '../notifications/notifications.service';

@Injectable()
export class AlertingService {
  private readonly logger = new Logger(AlertingService.name);
  private readonly rulesFile = path.join(process.cwd(), '..', 'data', 'alert-rules.json');
  private readonly channelsFile = path.join(process.cwd(), '..', 'data', 'alert-channels.json');
  private readonly alertsFile = path.join(process.cwd(), '..', 'data', 'alert-history.json');
  private alertingEngine: AlertingEngine;
  private rules: Map<string, AlertRuleEntity> = new Map();
  private channels: Map<string, AlertChannelEntity> = new Map();
  private alerts: AlertEntity[] = [];

  constructor(
    private readonly moduleRef: ModuleRef,
  ) {
    this.alertingEngine = new AlertingEngine();
    this.setupEventListeners();
    this.loadData().catch(err => {
      this.logger.error('Error loading alerting data on startup:', err);
    });
  }

  private setupEventListeners(): void {
    // Listen for alert creation events
    this.alertingEngine.on('alert_created', async (alert: Alert) => {
      await this.handleAlertCreated(alert);
    });

    // Listen for aggregated alerts
    this.alertingEngine.on('alert_aggregated', async (alert: Alert) => {
      await this.handleAlertCreated(alert);
    });
  }

  private async loadData(): Promise<void> {
    try {
      // Load alert rules
      try {
        await fs.mkdir(path.dirname(this.rulesFile), { recursive: true });
        const rulesData = await fs.readFile(this.rulesFile, 'utf-8');
        if (rulesData && rulesData.trim()) {
          const rulesArray = JSON.parse(rulesData);
          for (const rule of rulesArray) {
            const ruleEntity: AlertRuleEntity = {
              ...rule,
              createdAt: new Date(rule.createdAt),
              updatedAt: new Date(rule.updatedAt),
              lastTriggered: rule.lastTriggered ? new Date(rule.lastTriggered) : undefined,
            };
            this.rules.set(rule.id, ruleEntity);
            this.alertingEngine.registerRule(ruleEntity);
          }
        }
      } catch {
        this.rules = new Map();
      }

      // Load alert channels
      try {
        await fs.mkdir(path.dirname(this.channelsFile), { recursive: true });
        const channelsData = await fs.readFile(this.channelsFile, 'utf-8');
        if (channelsData && channelsData.trim()) {
          const channelsArray = JSON.parse(channelsData);
          for (const channel of channelsArray) {
            const channelEntity: AlertChannelEntity = {
              ...channel,
              createdAt: new Date(channel.createdAt),
              updatedAt: new Date(channel.updatedAt),
            };
            this.channels.set(channel.id, channelEntity);
            this.alertingEngine.registerChannel(channelEntity);
          }
        }
      } catch {
        this.channels = new Map();
      }

      // Load alert history
      try {
        await fs.mkdir(path.dirname(this.alertsFile), { recursive: true });
        const alertsData = await fs.readFile(this.alertsFile, 'utf-8');
        if (alertsData && alertsData.trim()) {
          this.alerts = JSON.parse(alertsData).map((a: any) => ({
            ...a,
            triggeredAt: new Date(a.triggeredAt),
            createdAt: new Date(a.createdAt),
            updatedAt: a.updatedAt ? new Date(a.updatedAt) : undefined,
          }));
        }
      } catch {
        this.alerts = [];
      }
    } catch (error) {
      this.logger.error('Error loading alerting data:', error);
    }
  }

  private async saveRules(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.rulesFile), { recursive: true });
      const rulesArray = Array.from(this.rules.values());
      await fs.writeFile(this.rulesFile, JSON.stringify(rulesArray, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving alert rules:', error);
      throw error;
    }
  }

  private async saveChannels(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.channelsFile), { recursive: true });
      const channelsArray = Array.from(this.channels.values());
      await fs.writeFile(this.channelsFile, JSON.stringify(channelsArray, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving alert channels:', error);
      throw error;
    }
  }

  private async saveAlerts(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.alertsFile), { recursive: true });
      // Keep only last 10,000 alerts
      const alertsToSave = this.alerts.slice(-10000);
      await fs.writeFile(this.alertsFile, JSON.stringify(alertsToSave, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving alert history:', error);
      throw error;
    }
  }

  /**
   * Create alert rule
   */
  async createRule(dto: CreateAlertRuleDto, userId?: string): Promise<AlertRuleEntity> {
    const rule: AlertRuleEntity = {
      id: uuidv4(),
      ...dto,
      enabled: dto.enabled !== undefined ? dto.enabled : true, // Default to true if not provided
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    this.rules.set(rule.id, rule);
    this.alertingEngine.registerRule(rule);
    await this.saveRules();

    this.logger.log(`Alert rule created: ${rule.id} (${rule.name})`);
    return rule;
  }

  /**
   * Get all alert rules
   */
  async getRules(): Promise<AlertRuleEntity[]> {
    return Array.from(this.rules.values());
  }

  /**
   * Get alert rule by ID
   */
  async getRuleById(id: string): Promise<AlertRuleEntity> {
    const rule = this.rules.get(id);
    if (!rule) {
      throw new Error(`Alert rule not found: ${id}`);
    }
    return rule;
  }

  /**
   * Update alert rule
   */
  async updateRule(id: string, dto: UpdateAlertRuleDto, userId?: string): Promise<AlertRuleEntity> {
    const existing = await this.getRuleById(id);
    const updated: AlertRuleEntity = {
      ...existing,
      ...dto,
      updatedAt: new Date(),
      updatedBy: userId,
    };

    this.rules.set(id, updated);
    this.alertingEngine.removeRule(id);
    this.alertingEngine.registerRule(updated);
    await this.saveRules();

    this.logger.log(`Alert rule updated: ${id}`);
    return updated;
  }

  /**
   * Delete alert rule
   */
  async deleteRule(id: string): Promise<void> {
    await this.getRuleById(id); // Verify exists
    this.rules.delete(id);
    this.alertingEngine.removeRule(id);
    await this.saveRules();

    this.logger.log(`Alert rule deleted: ${id}`);
  }

  /**
   * Test alert rule against a finding
   */
  async testRule(ruleId: string, finding: UnifiedFinding): Promise<Alert[]> {
    const rule = await this.getRuleById(ruleId);
    return this.alertingEngine.evaluateFinding(finding);
  }

  /**
   * Create alert channel
   */
  async createChannel(dto: CreateAlertChannelDto, userId?: string): Promise<AlertChannelEntity> {
    const channel: AlertChannelEntity = {
      id: uuidv4(),
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    this.channels.set(channel.id, channel);
    this.alertingEngine.registerChannel(channel);
    await this.saveChannels();

    this.logger.log(`Alert channel created: ${channel.id} (${channel.name})`);
    return channel;
  }

  /**
   * Get all alert channels
   */
  async getChannels(): Promise<AlertChannelEntity[]> {
    return Array.from(this.channels.values());
  }

  /**
   * Get alert channel by ID
   */
  async getChannelById(id: string): Promise<AlertChannelEntity> {
    const channel = this.channels.get(id);
    if (!channel) {
      throw new Error(`Alert channel not found: ${id}`);
    }
    return channel;
  }

  /**
   * Update alert channel
   */
  async updateChannel(id: string, dto: UpdateAlertChannelDto, userId?: string): Promise<AlertChannelEntity> {
    const existing = await this.getChannelById(id);
    const updated: AlertChannelEntity = {
      ...existing,
      ...dto,
      updatedAt: new Date(),
      updatedBy: userId,
    };

    this.channels.set(id, updated);
    this.alertingEngine.removeChannel(id);
    this.alertingEngine.registerChannel(updated);
    await this.saveChannels();

    this.logger.log(`Alert channel updated: ${id}`);
    return updated;
  }

  /**
   * Delete alert channel
   */
  async deleteChannel(id: string): Promise<void> {
    await this.getChannelById(id); // Verify exists
    this.channels.delete(id);
    this.alertingEngine.removeChannel(id);
    await this.saveChannels();

    this.logger.log(`Alert channel deleted: ${id}`);
  }

  /**
   * Evaluate finding against all rules
   */
  async evaluateFinding(finding: UnifiedFinding): Promise<Alert[]> {
    return this.alertingEngine.evaluateFinding(finding);
  }

  /**
   * Query alert history
   */
  async queryAlerts(query: AlertQueryDto): Promise<{ alerts: AlertEntity[]; total: number; page: number; limit: number }> {
    let filtered = [...this.alerts];

    if (query.ruleId) {
      filtered = filtered.filter(a => a.ruleId === query.ruleId);
    }

    if (query.status) {
      filtered = filtered.filter(a => a.status === query.status);
    }

    if (query.severity) {
      filtered = filtered.filter(a => a.severity === query.severity);
    }

    if (query.startDate) {
      const start = new Date(query.startDate);
      filtered = filtered.filter(a => a.triggeredAt >= start);
    }

    if (query.endDate) {
      const end = new Date(query.endDate);
      filtered = filtered.filter(a => a.triggeredAt <= end);
    }

    // Sort by triggeredAt descending
    filtered.sort((a, b) => b.triggeredAt.getTime() - a.triggeredAt.getTime());

    const total = filtered.length;
    const page = query.page || 1;
    const limit = query.limit || 50;
    const start = (page - 1) * limit;
    const end = start + limit;
    const paginated = filtered.slice(start, end);

    return {
      alerts: paginated,
      total,
      page,
      limit,
    };
  }

  /**
   * Get alert by ID
   */
  async getAlertById(id: string): Promise<AlertEntity> {
    const alert = this.alerts.find(a => a.id === id);
    if (!alert) {
      throw new Error(`Alert not found: ${id}`);
    }
    return alert;
  }

  /**
   * Retry failed alert
   */
  async retryAlert(id: string): Promise<AlertEntity> {
    const alert = await this.getAlertById(id);
    if (alert.status !== 'failed') {
      throw new Error(`Alert ${id} is not in failed status`);
    }

    alert.status = 'pending';
    alert.updatedAt = new Date();
    await this.saveAlerts();
    await this.sendAlert(alert);

    return alert;
  }

  /**
   * Handle alert created event
   */
  private async handleAlertCreated(alert: Alert): Promise<void> {
    const alertEntity: AlertEntity = {
      ...alert,
      createdAt: new Date(),
    };

    this.alerts.push(alertEntity);
    await this.saveAlerts();

    // Send alert via channels
    await this.sendAlert(alertEntity);
  }

  /**
   * Send alert via configured channels
   */
  private async sendAlert(alert: AlertEntity): Promise<void> {
    try {
      for (const channelId of alert.channels) {
        const channel = this.channels.get(channelId);
        if (!channel || !channel.enabled) {
          continue;
        }

        try {
          await this.sendViaChannel(alert, channel);
          alert.status = 'sent';
        } catch (error) {
          this.logger.error(`Failed to send alert ${alert.id} via channel ${channelId}:`, error);
          alert.status = 'failed';
        }
      }

      alert.updatedAt = new Date();
      await this.saveAlerts();
    } catch (error) {
      this.logger.error(`Error sending alert ${alert.id}:`, error);
      alert.status = 'failed';
      alert.updatedAt = new Date();
      await this.saveAlerts();
    }
  }

  /**
   * Send alert via specific channel
   */
  private async sendViaChannel(alert: AlertEntity, channel: AlertChannelEntity): Promise<void> {
    switch (channel.type) {
      case 'email':
        await this.sendEmail(alert, channel);
        break;
      case 'slack':
        await this.sendSlack(alert, channel);
        break;
      case 'pagerduty':
        await this.sendPagerDuty(alert, channel);
        break;
      case 'teams':
        await this.sendTeams(alert, channel);
        break;
      case 'webhook':
        await this.sendWebhook(alert, channel);
        break;
      default:
        this.logger.warn(`Unsupported channel type: ${channel.type}`);
    }
  }

  /**
   * Send email alert (via notifications service)
   */
  private async sendEmail(alert: AlertEntity, channel: AlertChannelEntity): Promise<void> {
    const email = channel.config.email || channel.config.to;
    if (!email) {
      throw new Error('Email address not configured');
    }

    // Use notifications service to send email
    // For now, create a notification - in production, integrate with email service
    const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
    if (notificationsService) {
      await notificationsService.createNotification({
        userId: email, // Use email as userId for now
        type: 'CRITICAL_FINDING' as any,
        title: alert.title,
        message: alert.message,
        metadata: {
          findingId: alert.findings[0]?.id,
          alertId: alert.id,
          severity: alert.severity,
        },
      });
    }
  }

  /**
   * Send Slack alert
   */
  private async sendSlack(alert: AlertEntity, channel: AlertChannelEntity): Promise<void> {
    const webhookUrl = channel.config.webhookUrl;
    if (!webhookUrl) {
      throw new Error('Slack webhook URL not configured');
    }

    // NOTE: Slack webhook integration is a stub implementation
    // Future implementation should use axios/fetch to POST formatted alert to Slack webhook
    // See: https://api.slack.com/messaging/webhooks
    this.logger.log(`Sending Slack alert to ${webhookUrl}: ${alert.title}`);
  }

  /**
   * Send PagerDuty alert
   */
  private async sendPagerDuty(alert: AlertEntity, channel: AlertChannelEntity): Promise<void> {
    const integrationKey = channel.config.integrationKey;
    if (!integrationKey) {
      throw new Error('PagerDuty integration key not configured');
    }

    // NOTE: PagerDuty integration is a stub implementation
    // Future implementation should use PagerDuty Events API v2
    // See: https://developer.pagerduty.com/api-reference/
    this.logger.log(`Sending PagerDuty alert: ${alert.title}`);
  }

  /**
   * Send Microsoft Teams alert
   */
  private async sendTeams(alert: AlertEntity, channel: AlertChannelEntity): Promise<void> {
    const webhookUrl = channel.config.webhookUrl;
    if (!webhookUrl) {
      throw new Error('Teams webhook URL not configured');
    }

    // NOTE: Microsoft Teams webhook integration is a stub implementation
    // Future implementation should POST formatted message card to Teams webhook
    // See: https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
    this.logger.log(`Sending Teams alert to ${webhookUrl}: ${alert.title}`);
  }

  /**
   * Send webhook alert
   */
  private async sendWebhook(alert: AlertEntity, channel: AlertChannelEntity): Promise<void> {
    const url = channel.config.url;
    if (!url) {
      throw new Error('Webhook URL not configured');
    }

    // NOTE: Generic webhook integration is a stub implementation
    // Future implementation should POST alert data to the configured webhook URL
    this.logger.log(`Sending webhook alert to ${url}: ${alert.title}`);
  }
}
