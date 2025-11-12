import { Injectable, NotFoundException } from '@nestjs/common';
import {
  SLAPolicy,
  SLAViolation,
  SLASeverity,
  SLAStatus,
  EscalationEvent,
  CreateSLAPolicyDto,
} from './entities/sla.entity';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class SLAService {
  private readonly policiesFile = path.join(process.cwd(), '..', '..', 'data', 'sla-policies.json');
  private readonly violationsFile = path.join(process.cwd(), '..', '..', 'data', 'sla-violations.json');
  private policies: SLAPolicy[] = [];
  private slaViolations: SLAViolation[] = [];

  constructor() {
    this.loadData().catch(err => {
      console.error('Error loading SLA data on startup:', err);
    });
    // Start periodic SLA checking
    this.startSLAChecker();
  }

  private async loadData(): Promise<void> {
    try {
      // Load policies
      try {
        const policiesData = await fs.readFile(this.policiesFile, 'utf-8');
        this.policies = JSON.parse(policiesData);
      } catch {
        this.policies = [];
      }

      // Load SLA violations
      try {
        const violationsData = await fs.readFile(this.violationsFile, 'utf-8');
        this.slaViolations = JSON.parse(violationsData);
      } catch {
        this.slaViolations = [];
      }
    } catch (error) {
      console.error('Error loading SLA data:', error);
    }
  }

  private async savePolicies(): Promise<void> {
    try {
      const dir = path.dirname(this.policiesFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.policiesFile, JSON.stringify(this.policies, null, 2));
    } catch (error) {
      console.error('Error saving SLA policies:', error);
      throw error;
    }
  }

  private async saveViolations(): Promise<void> {
    try {
      const dir = path.dirname(this.violationsFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.violationsFile, JSON.stringify(this.slaViolations, null, 2));
    } catch (error) {
      console.error('Error saving SLA violations:', error);
      throw error;
    }
  }

  // Policy Management
  async createPolicy(dto: CreateSLAPolicyDto): Promise<SLAPolicy> {
    const policy: SLAPolicy = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description,
      severity: dto.severity,
      targetResolutionHours: dto.targetResolutionHours,
      warningThresholdHours: dto.warningThresholdHours,
      escalationRules: dto.escalationRules.map(rule => ({
        ...rule,
        id: uuidv4(),
      })),
      enabled: dto.enabled,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.policies.push(policy);
    await this.savePolicies();

    return policy;
  }

  async findAllPolicies(): Promise<SLAPolicy[]> {
    return this.policies;
  }

  async findOnePolicy(id: string): Promise<SLAPolicy> {
    const policy = this.policies.find(p => p.id === id);
    if (!policy) {
      throw new NotFoundException(`SLA Policy with ID ${id} not found`);
    }
    return policy;
  }

  async updatePolicy(id: string, updates: Partial<SLAPolicy>): Promise<SLAPolicy> {
    const index = this.policies.findIndex(p => p.id === id);
    if (index === -1) {
      throw new NotFoundException(`SLA Policy with ID ${id} not found`);
    }

    this.policies[index] = {
      ...this.policies[index],
      ...updates,
      updatedAt: new Date(),
    };

    await this.savePolicies();
    return this.policies[index];
  }

  async deletePolicy(id: string): Promise<void> {
    const index = this.policies.findIndex(p => p.id === id);
    if (index === -1) {
      throw new NotFoundException(`SLA Policy with ID ${id} not found`);
    }

    this.policies.splice(index, 1);
    await this.savePolicies();
  }

  // SLA Violation Management
  async createSLAViolation(violationId: string, severity: SLASeverity): Promise<SLAViolation> {
    // Find matching SLA policy
    const policy = this.policies.find(
      p => p.severity === severity && p.enabled
    );

    if (!policy) {
      throw new NotFoundException(`No SLA policy found for severity: ${severity}`);
    }

    const now = new Date();
    const targetResolutionAt = new Date(now.getTime() + policy.targetResolutionHours * 60 * 60 * 1000);
    const warningThresholdAt = new Date(now.getTime() + policy.warningThresholdHours * 60 * 60 * 1000);

    const slaViolation: SLAViolation = {
      id: uuidv4(),
      violationId,
      slaPolicyId: policy.id,
      status: SLAStatus.ON_TRACK,
      detectedAt: now,
      targetResolutionAt,
      warningThresholdAt,
      escalationHistory: [],
      createdAt: now,
      updatedAt: now,
    };

    this.slaViolations.push(slaViolation);
    await this.saveViolations();

    return slaViolation;
  }

  async findAllSLAViolations(violationId?: string): Promise<SLAViolation[]> {
    if (violationId) {
      return this.slaViolations.filter(sv => sv.violationId === violationId);
    }
    return this.slaViolations;
  }

  async findOneSLAViolation(id: string): Promise<SLAViolation> {
    const slaViolation = this.slaViolations.find(sv => sv.id === id);
    if (!slaViolation) {
      throw new NotFoundException(`SLA Violation with ID ${id} not found`);
    }
    return slaViolation;
  }

  async resolveSLAViolation(id: string): Promise<SLAViolation> {
    const slaViolation = await this.findOneSLAViolation(id);
    
    slaViolation.status = SLAStatus.ON_TRACK;
    slaViolation.resolvedAt = new Date();
    slaViolation.updatedAt = new Date();

    await this.saveViolations();
    return slaViolation;
  }

  // SLA Checking and Escalation
  private startSLAChecker(): void {
    // Check SLA violations every 5 minutes
    setInterval(() => {
      this.checkSLAViolations().catch(err => {
        console.error('Error checking SLA violations:', err);
      });
    }, 5 * 60 * 1000);
  }

  private async checkSLAViolations(): Promise<void> {
    const now = new Date();
    
    for (const slaViolation of this.slaViolations) {
      if (slaViolation.resolvedAt) {
        continue; // Already resolved
      }

      const policy = this.policies.find(p => p.id === slaViolation.slaPolicyId);
      if (!policy || !policy.enabled) {
        continue;
      }

      const hoursSinceDetection = (now.getTime() - slaViolation.detectedAt.getTime()) / (1000 * 60 * 60);
      const previousStatus = slaViolation.status;

      // Check if breached
      if (hoursSinceDetection >= policy.targetResolutionHours) {
        slaViolation.status = SLAStatus.BREACHED;
      } else if (hoursSinceDetection >= policy.warningThresholdHours) {
        slaViolation.status = SLAStatus.AT_RISK;
      } else {
        slaViolation.status = SLAStatus.ON_TRACK;
      }

      // Check escalation rules
      if (slaViolation.status !== previousStatus || slaViolation.status === SLAStatus.AT_RISK) {
        await this.processEscalations(slaViolation, policy, hoursSinceDetection);
      }

      slaViolation.updatedAt = now;
    }

    await this.saveViolations();
  }

  private async processEscalations(
    slaViolation: SLAViolation,
    policy: SLAPolicy,
    hoursSinceDetection: number
  ): Promise<void> {
    for (const rule of policy.escalationRules) {
      // Check if this escalation rule should trigger
      if (hoursSinceDetection >= rule.triggerHours) {
        // Check if we've already triggered this escalation
        const alreadyTriggered = slaViolation.escalationHistory.some(
          e => e.metadata?.ruleId === rule.id
        );

        if (!alreadyTriggered) {
          const escalationEvent: EscalationEvent = {
            id: uuidv4(),
            type: hoursSinceDetection >= policy.targetResolutionHours ? 'breach' : 'escalation',
            action: rule.action,
            target: rule.target,
            timestamp: new Date(),
            message: rule.message,
            metadata: {
              ruleId: rule.id,
              triggerHours: rule.triggerHours,
            },
          };

          slaViolation.escalationHistory.push(escalationEvent);
          
          if (rule.action === 'escalate' || rule.action === 'assign') {
            slaViolation.currentAssignee = rule.target;
            slaViolation.escalatedAt = new Date();
          }

          // In a real implementation, this would trigger notifications, create tickets, etc.
          console.log(`SLA Escalation triggered: ${escalationEvent.type} for violation ${slaViolation.violationId}`);
        }
      }
    }
  }

  async getSLAStats(): Promise<{
    total: number;
    onTrack: number;
    atRisk: number;
    breached: number;
    averageResolutionTime: number;
  }> {
    const total = this.slaViolations.length;
    const onTrack = this.slaViolations.filter(sv => sv.status === SLAStatus.ON_TRACK).length;
    const atRisk = this.slaViolations.filter(sv => sv.status === SLAStatus.AT_RISK).length;
    const breached = this.slaViolations.filter(sv => sv.status === SLAStatus.BREACHED).length;

    const resolved = this.slaViolations.filter(sv => sv.resolvedAt);
    const averageResolutionTime = resolved.length > 0
      ? resolved.reduce((sum, sv) => {
          const resolutionTime = (sv.resolvedAt!.getTime() - sv.detectedAt.getTime()) / (1000 * 60 * 60);
          return sum + resolutionTime;
        }, 0) / resolved.length
      : 0;

    return {
      total,
      onTrack,
      atRisk,
      breached,
      averageResolutionTime,
    };
  }
}

