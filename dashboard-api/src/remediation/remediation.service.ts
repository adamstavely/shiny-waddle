import { Injectable } from '@nestjs/common';
import { ViolationEntity } from '../violations/entities/violation.entity';
import { ViolationSeverity } from '../violations/dto/create-violation.dto';
import { TicketingService } from '../ticketing/ticketing.service';
import { AppLogger } from '../common/services/logger.service';

export interface RemediationAction {
  type: 'create-ticket' | 'assign' | 'escalate' | 'auto-fix' | 'notify';
  target?: string;
  metadata?: Record<string, any>;
}

export interface RemediationRule {
  id: string;
  name: string;
  conditions: {
    severity?: ViolationSeverity[];
    type?: string[];
    application?: string[];
    team?: string[];
  };
  actions: RemediationAction[];
  enabled: boolean;
}

@Injectable()
export class RemediationService {
  private remediationRules: RemediationRule[] = [];

  constructor(
    private readonly ticketingService: TicketingService,
  ) {}

  async processViolation(violation: ViolationEntity): Promise<void> {
    // Find matching remediation rules
    const matchingRules = this.remediationRules.filter(rule => {
      if (!rule.enabled) return false;

      const conditions = rule.conditions;
      
      if (conditions.severity && !conditions.severity.includes(violation.severity)) {
        return false;
      }
      
      if (conditions.type && !conditions.type.includes(violation.type)) {
        return false;
      }
      
      if (conditions.application && violation.application && !conditions.application.includes(violation.application)) {
        return false;
      }
      
      if (conditions.team && violation.team && !conditions.team.includes(violation.team)) {
        return false;
      }

      return true;
    });

    // Execute actions for each matching rule
    for (const rule of matchingRules) {
      for (const action of rule.actions) {
        await this.executeAction(action, violation);
      }
    }

  }

  private async executeAction(action: RemediationAction, violation: ViolationEntity): Promise<void> {
    switch (action.type) {
      case 'create-ticket':
        await this.createTicket(violation, action);
        break;
      case 'assign':
        await this.assignViolation(violation, action.target);
        break;
      case 'escalate':
        await this.escalateViolation(violation, action.target);
        break;
      case 'auto-fix':
        await this.attemptAutoFix(violation, action);
        break;
      case 'notify':
        await this.notify(violation, action);
        break;
    }
  }

  private async createTicket(violation: ViolationEntity, action: RemediationAction): Promise<void> {
    // Get enabled ticketing integrations
    const integrations = await this.ticketingService.findAllIntegrations();
    const enabledIntegration = integrations.find(i => i.enabled);

    if (!enabledIntegration) {
      this.logger.warn(`No enabled ticketing integration found for violation: ${violation.id}`);
      return;
    }

    const priority = this.mapSeverityToPriority(violation.severity);
    const description = this.buildTicketDescription(violation);

    try {
      await this.ticketingService.createTicket(enabledIntegration.id, {
        violationId: violation.id,
        title: violation.title,
        description,
        priority,
        assignee: violation.assignedTo,
        labels: action.metadata?.labels || [],
      });
    } catch (error) {
      this.logger.error('Failed to create ticket', error instanceof Error ? error.stack : String(error), { violationId: violation.id });
    }
  }

  private async assignViolation(violation: ViolationEntity, assignee?: string): Promise<void> {
    // This would update the violation assignment
    this.logger.debug(`Assigning violation ${violation.id} to ${assignee}`);
  }

  private async escalateViolation(violation: ViolationEntity, target?: string): Promise<void> {
    // This would escalate the violation
    this.logger.debug(`Escalating violation ${violation.id} to ${target}`);
  }

  private async attemptAutoFix(violation: ViolationEntity, action: RemediationAction): Promise<void> {
    // Attempt automated remediation based on violation type
    // This is a placeholder - real implementation would have specific fix logic
    this.logger.debug(`Attempting auto-fix for violation ${violation.id}`);
    
    // Example: If violation has remediation suggestions, try to apply them
    if (violation.remediationSuggestions && violation.remediationSuggestions.length > 0) {
      // In a real implementation, this would:
      // 1. Analyze the remediation suggestion
      // 2. Determine if it's safe to auto-apply
      // 3. Create a PR or apply the fix directly
      // 4. Verify the fix
    }
  }

  private async notify(violation: ViolationEntity, action: RemediationAction): Promise<void> {
    // Send notifications via configured channels
    this.logger.debug(`Notifying about violation ${violation.id} via ${action.metadata?.channels}`);
  }

  private mapSeverityToPriority(severity: ViolationSeverity): string {
    const mapping: Record<ViolationSeverity, string> = {
      critical: 'highest',
      high: 'high',
      medium: 'medium',
      low: 'low',
    };
    return mapping[severity] || 'medium';
  }

  private buildTicketDescription(violation: ViolationEntity): string {
    let description = violation.description || '';

    if (violation.policyName) {
      description += `\n\nPolicy: ${violation.policyName}`;
    }

    if (violation.remediationSuggestions && violation.remediationSuggestions.length > 0) {
      description += '\n\nRemediation Suggestions:';
      violation.remediationSuggestions.forEach((suggestion, index) => {
        description += `\n${index + 1}. ${suggestion}`;
      });
    }

    if (violation.resource) {
      description += `\n\nAffected Resource: ${violation.resource}`;
    }

    return description;
  }

  // Remediation Rule Management
  async createRule(rule: RemediationRule): Promise<RemediationRule> {
    this.remediationRules.push(rule);
    return rule;
  }

  async findAllRules(): Promise<RemediationRule[]> {
    return this.remediationRules;
  }

  async updateRule(id: string, updates: Partial<RemediationRule>): Promise<RemediationRule> {
    const index = this.remediationRules.findIndex(r => r.id === id);
    if (index === -1) {
      throw new Error(`Remediation rule with ID ${id} not found`);
    }

    this.remediationRules[index] = {
      ...this.remediationRules[index],
      ...updates,
    };

    return this.remediationRules[index];
  }

  async deleteRule(id: string): Promise<void> {
    const index = this.remediationRules.findIndex(r => r.id === id);
    if (index !== -1) {
      this.remediationRules.splice(index, 1);
    }
  }
}

