import { Injectable, Logger } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { GapAnalysisService, GapAnalysis } from './gap-analysis.service';
import { DataTagComparisonService } from './data-tag-comparison.service';
import { CacheService } from './cache.service';

export interface AutomationRule {
  id: string;
  name: string;
  description: string;
  trigger: {
    type: 'gap-detected' | 'policy-change' | 'schedule' | 'compliance-threshold';
    conditions: Record<string, any>;
  };
  actions: Array<{
    type: 'auto-fix' | 'notify' | 'create-ticket' | 'escalate';
    config: Record<string, any>;
  }>;
  enabled: boolean;
  requiresApproval: boolean;
  createdBy: string;
  createdAt: Date;
}

export interface RemediationResult {
  success: boolean;
  action: string;
  message: string;
  changes?: Record<string, any>;
}

@Injectable()
export class AutomationService {
  private readonly logger = new Logger(AutomationService.name);
  private readonly rules: Map<string, AutomationRule> = new Map();

  constructor(
    private readonly policiesService: PoliciesService,
    private readonly gapAnalysisService: GapAnalysisService,
    private readonly tagComparisonService: DataTagComparisonService,
    private readonly cacheService: CacheService,
  ) {}

  /**
   * Create an automation rule
   */
  async createRule(rule: Omit<AutomationRule, 'id' | 'createdAt'>): Promise<AutomationRule> {
    const id = `rule-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const automationRule: AutomationRule = {
      ...rule,
      id,
      createdAt: new Date(),
    };

    this.rules.set(id, automationRule);
    this.logger.log(`Created automation rule: ${id} (${rule.name})`);

    return automationRule;
  }

  /**
   * Get all automation rules
   */
  async getAllRules(): Promise<AutomationRule[]> {
    return Array.from(this.rules.values());
  }

  /**
   * Get a specific rule
   */
  async getRule(id: string): Promise<AutomationRule | null> {
    return this.rules.get(id) || null;
  }

  /**
   * Update an automation rule
   */
  async updateRule(id: string, updates: Partial<AutomationRule>): Promise<AutomationRule> {
    const rule = this.rules.get(id);
    if (!rule) {
      throw new Error(`Rule ${id} not found`);
    }

    const updated = { ...rule, ...updates };
    this.rules.set(id, updated);
    this.logger.log(`Updated automation rule: ${id}`);

    return updated;
  }

  /**
   * Delete an automation rule
   */
  async deleteRule(id: string): Promise<void> {
    if (this.rules.delete(id)) {
      this.logger.log(`Deleted automation rule: ${id}`);
    }
  }

  /**
   * Execute automation rules for a detected gap
   */
  async processGap(gapId: string, gap: any): Promise<RemediationResult[]> {
    const results: RemediationResult[] = [];
    const applicableRules = Array.from(this.rules.values()).filter(
      rule => rule.enabled && this.matchesTrigger(rule, 'gap-detected', gap)
    );

    this.logger.log(`Found ${applicableRules.length} applicable rules for gap ${gapId}`);

    for (const rule of applicableRules) {
      try {
        if (rule.requiresApproval) {
          this.logger.log(`Rule ${rule.id} requires approval, skipping auto-execution`);
          results.push({
            success: false,
            action: rule.actions[0]?.type || 'unknown',
            message: `Rule "${rule.name}" requires approval before execution`,
          });
          continue;
        }

        for (const action of rule.actions) {
          const result = await this.executeAction(action, gap);
          results.push(result);
        }
      } catch (error: any) {
        this.logger.error(`Error executing rule ${rule.id}:`, error);
        results.push({
          success: false,
          action: rule.actions[0]?.type || 'unknown',
          message: `Error executing rule: ${error.message}`,
        });
      }
    }

    return results;
  }

  /**
   * Execute automation rules for a policy change
   */
  async processPolicyChange(policyId: string, changeType: 'created' | 'modified' | 'deleted'): Promise<RemediationResult[]> {
    const results: RemediationResult[] = [];
    const applicableRules = Array.from(this.rules.values()).filter(
      rule => rule.enabled && this.matchesTrigger(rule, 'policy-change', { policyId, changeType })
    );

    this.logger.log(`Found ${applicableRules.length} applicable rules for policy change ${policyId}`);

    for (const rule of applicableRules) {
      try {
        for (const action of rule.actions) {
          const result = await this.executeAction(action, { policyId, changeType });
          results.push(result);
        }
      } catch (error: any) {
        this.logger.error(`Error executing rule ${rule.id}:`, error);
        results.push({
          success: false,
          action: rule.actions[0]?.type || 'unknown',
          message: `Error executing rule: ${error.message}`,
        });
      }
    }

    return results;
  }

  /**
   * Check if a rule's trigger matches the event
   */
  private matchesTrigger(rule: AutomationRule, eventType: string, eventData: any): boolean {
    if (rule.trigger.type !== eventType) {
      return false;
    }

    // Check conditions
    const conditions = rule.trigger.conditions;
    if (!conditions || Object.keys(conditions).length === 0) {
      return true; // No conditions means match all
    }

    // Example condition matching
    if (conditions.severity && eventData.severity !== conditions.severity) {
      return false;
    }

    if (conditions.policyType && eventData.policyType !== conditions.policyType) {
      return false;
    }

    return true;
  }

  /**
   * Execute an automation action
   */
  private async executeAction(action: AutomationRule['actions'][0], context: any): Promise<RemediationResult> {
    switch (action.type) {
      case 'auto-fix':
        return await this.autoFix(action.config, context);
      case 'notify':
        return await this.notify(action.config, context);
      case 'create-ticket':
        return await this.createTicket(action.config, context);
      case 'escalate':
        return await this.escalate(action.config, context);
      default:
        throw new Error(`Unknown action type: ${action.type}`);
    }
  }

  /**
   * Auto-fix a gap (e.g., add missing tags)
   */
  private async autoFix(config: Record<string, any>, context: any): Promise<RemediationResult> {
    try {
      // Only auto-fix low-risk gaps
      if (context.severity && ['high', 'critical'].includes(context.severity)) {
        return {
          success: false,
          action: 'auto-fix',
          message: 'High-severity gaps require manual review',
        };
      }

      // Example: Auto-fix missing tags
      if (config.fixType === 'add-tags' && context.resourceId && context.missingTags) {
        // In production, this would call the resource service to update tags
        this.logger.log(`Auto-fixing tags for resource ${context.resourceId}`);
        
        return {
          success: true,
          action: 'auto-fix',
          message: `Automatically added ${context.missingTags.length} missing tags`,
          changes: {
            resourceId: context.resourceId,
            tagsAdded: context.missingTags,
          },
        };
      }

      return {
        success: false,
        action: 'auto-fix',
        message: 'Auto-fix not applicable for this gap',
      };
    } catch (error: any) {
      this.logger.error('Error in auto-fix:', error);
      return {
        success: false,
        action: 'auto-fix',
        message: `Auto-fix failed: ${error.message}`,
      };
    }
  }

  /**
   * Send notification
   */
  private async notify(config: Record<string, any>, context: any): Promise<RemediationResult> {
    try {
      const recipients = config.recipients || [];
      const message = config.message || 'Policy automation notification';

      // In production, this would send actual notifications
      this.logger.log(`Sending notification to ${recipients.join(', ')}: ${message}`);

      return {
        success: true,
        action: 'notify',
        message: `Notification sent to ${recipients.length} recipient(s)`,
      };
    } catch (error: any) {
      return {
        success: false,
        action: 'notify',
        message: `Notification failed: ${error.message}`,
      };
    }
  }

  /**
   * Create a ticket
   */
  private async createTicket(config: Record<string, any>, context: any): Promise<RemediationResult> {
    try {
      // In production, this would integrate with ticketing system
      this.logger.log(`Creating ticket: ${config.title || 'Policy issue'}`);

      return {
        success: true,
        action: 'create-ticket',
        message: 'Ticket created successfully',
        changes: {
          ticketId: `ticket-${Date.now()}`,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        action: 'create-ticket',
        message: `Ticket creation failed: ${error.message}`,
      };
    }
  }

  /**
   * Escalate issue
   */
  private async escalate(config: Record<string, any>, context: any): Promise<RemediationResult> {
    try {
      const escalationLevel = config.level || 'manager';
      // In production, this would escalate to appropriate stakeholders
      this.logger.log(`Escalating to ${escalationLevel}`);

      return {
        success: true,
        action: 'escalate',
        message: `Issue escalated to ${escalationLevel}`,
      };
    } catch (error: any) {
      return {
        success: false,
        action: 'escalate',
        message: `Escalation failed: ${error.message}`,
      };
    }
  }

  /**
   * Run scheduled gap analysis
   */
  async runScheduledGapAnalysis(policyId?: string): Promise<GapAnalysis> {
    this.logger.log(`Running scheduled gap analysis${policyId ? ` for policy ${policyId}` : ''}`);

    const analysis = await this.gapAnalysisService.analyzeGaps(policyId);

    // Process gaps through automation rules
    for (const gap of analysis.gaps) {
      await this.processGap(gap.id, gap);
    }

    // Invalidate cache
    if (policyId) {
      await this.cacheService.invalidatePolicyCache(policyId);
    }

    return analysis;
  }
}
