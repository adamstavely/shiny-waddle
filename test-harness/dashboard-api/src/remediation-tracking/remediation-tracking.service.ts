import { Injectable, NotFoundException } from '@nestjs/common';
import {
  RemediationTracking,
  RemediationMilestone,
  RemediationStep,
  RecurrenceEvent,
  RemediationMetrics,
  CreateRemediationTrackingDto,
} from './entities/remediation-tracking.entity';
import { ViolationsService } from '../violations/violations.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class RemediationTrackingService {
  private readonly trackingFile = path.join(process.cwd(), '..', '..', 'data', 'remediation-tracking.json');
  private trackings: RemediationTracking[] = [];

  constructor(private readonly violationsService: ViolationsService) {
    this.loadTrackings().catch(err => {
      console.error('Error loading remediation tracking on startup:', err);
    });
  }

  private async loadTrackings(): Promise<void> {
    try {
      const data = await fs.readFile(this.trackingFile, 'utf-8');
      this.trackings = JSON.parse(data);
    } catch {
      this.trackings = [];
    }
  }

  private async saveTrackings(): Promise<void> {
    try {
      const dir = path.dirname(this.trackingFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.trackingFile, JSON.stringify(this.trackings, null, 2));
    } catch (error) {
      console.error('Error saving remediation tracking:', error);
      throw error;
    }
  }

  async createTracking(dto: CreateRemediationTrackingDto): Promise<RemediationTracking> {
    // Check if this violation already has tracking
    const existing = this.trackings.find(t => t.violationId === dto.violationId);
    if (existing) {
      throw new Error(`Remediation tracking already exists for violation ${dto.violationId}`);
    }

    // Check for recurrence
    const violation = await this.violationsService.findOne(dto.violationId);
    const isRecurrence = await this.checkRecurrence(dto.violationId, violation);
    
    let originalViolationId: string | undefined;
    let recurrenceCount = 0;
    
    if (isRecurrence) {
      // Find original violation
      const originalTracking = this.trackings.find(t => 
        t.violationId !== dto.violationId && 
        this.isSameViolation(violation, t.violationId)
      );
      if (originalTracking) {
        originalViolationId = originalTracking.violationId;
        recurrenceCount = originalTracking.recurrenceCount + 1;
      }
    }

    const tracking: RemediationTracking = {
      id: uuidv4(),
      violationId: dto.violationId,
      status: 'not-started',
      progress: 0,
      milestones: (dto.milestones || []).map(m => ({
        ...m,
        id: uuidv4(),
      })),
      remediationSteps: (dto.remediationSteps || []).map(s => ({
        ...s,
        id: uuidv4(),
      })),
      effectiveness: 'pending',
      isRecurrence,
      originalViolationId,
      recurrenceCount,
      recurrenceHistory: [],
      assignedTo: dto.assignedTo,
      remediationMethod: dto.remediationMethod || 'manual',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.trackings.push(tracking);
    await this.saveTrackings();

    return tracking;
  }

  async findAllTrackings(violationId?: string): Promise<RemediationTracking[]> {
    if (violationId) {
      return this.trackings.filter(t => t.violationId === violationId);
    }
    return this.trackings;
  }

  async findOneTracking(id: string): Promise<RemediationTracking> {
    const tracking = this.trackings.find(t => t.id === id);
    if (!tracking) {
      throw new NotFoundException(`Remediation tracking with ID ${id} not found`);
    }
    return tracking;
  }

  async findByViolationId(violationId: string): Promise<RemediationTracking | null> {
    return this.trackings.find(t => t.violationId === violationId) || null;
  }

  async startRemediation(id: string, actor: string): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    tracking.status = 'in-progress';
    tracking.startedAt = new Date();
    tracking.updatedAt = new Date();

    // Calculate time to start
    const violation = await this.violationsService.findOne(tracking.violationId);
    if (violation.detectedAt) {
      const detectedAt = new Date(violation.detectedAt);
      tracking.timeToStart = (tracking.startedAt.getTime() - detectedAt.getTime()) / (1000 * 60 * 60);
    }

    await this.saveTrackings();
    return tracking;
  }

  async updateProgress(
    id: string,
    progress: number,
    currentStep?: string,
    milestoneId?: string
  ): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    tracking.progress = Math.max(0, Math.min(100, progress));
    tracking.currentStep = currentStep;
    tracking.updatedAt = new Date();

    if (milestoneId) {
      const milestone = tracking.milestones.find(m => m.id === milestoneId);
      if (milestone) {
        milestone.status = progress >= 100 ? 'completed' : 'in-progress';
        if (milestone.status === 'completed' && !milestone.completedAt) {
          milestone.completedAt = new Date();
          if (tracking.startedAt && milestone.estimatedHours) {
            milestone.actualHours = (milestone.completedAt.getTime() - tracking.startedAt!.getTime()) / (1000 * 60 * 60);
          }
        }
      }
    }

    await this.saveTrackings();
    return tracking;
  }

  async completeRemediation(
    id: string,
    actor: string,
    effectiveness?: 'effective' | 'ineffective' | 'unknown',
    effectivenessReason?: string
  ): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    tracking.status = 'completed';
    tracking.progress = 100;
    tracking.completedAt = new Date();
    tracking.effectiveness = effectiveness || 'pending';
    tracking.effectivenessReason = effectivenessReason;
    tracking.updatedAt = new Date();

    // Calculate time to remediation
    const violation = await this.violationsService.findOne(tracking.violationId);
    if (violation.detectedAt && tracking.startedAt) {
      tracking.timeToRemediation = (tracking.completedAt.getTime() - new Date(violation.detectedAt).getTime()) / (1000 * 60 * 60);
    }

    // Mark all milestones as completed
    tracking.milestones.forEach(milestone => {
      if (milestone.status !== 'completed' && milestone.status !== 'skipped') {
        milestone.status = 'completed';
        milestone.completedAt = tracking.completedAt;
      }
    });

    await this.saveTrackings();
    return tracking;
  }

  async verifyRemediation(
    id: string,
    verifiedBy: string,
    verificationTestId: string,
    effective: boolean
  ): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    tracking.effectiveness = effective ? 'effective' : 'ineffective';
    tracking.verifiedAt = new Date();
    tracking.verifiedBy = verifiedBy;
    tracking.verificationTestId = verificationTestId;
    tracking.updatedAt = new Date();

    await this.saveTrackings();
    return tracking;
  }

  async trackRecurrence(violationId: string): Promise<void> {
    const tracking = await this.findByViolationId(violationId);
    if (!tracking) return;

    const violation = await this.violationsService.findOne(violationId);
    
    const recurrenceEvent: RecurrenceEvent = {
      id: uuidv4(),
      violationId,
      detectedAt: violation.detectedAt ? new Date(violation.detectedAt) : new Date(),
      resolvedAt: violation.resolvedAt ? new Date(violation.resolvedAt) : undefined,
      remediationMethod: tracking.remediationMethod,
    };

    if (recurrenceEvent.detectedAt && recurrenceEvent.resolvedAt) {
      recurrenceEvent.timeToRemediation = 
        (recurrenceEvent.resolvedAt.getTime() - recurrenceEvent.detectedAt.getTime()) / (1000 * 60 * 60);
    }

    tracking.recurrenceHistory.push(recurrenceEvent);
    tracking.recurrenceCount = tracking.recurrenceHistory.length;
    tracking.isRecurrence = true;
    tracking.updatedAt = new Date();

    await this.saveTrackings();
  }

  async getMetrics(violationId?: string): Promise<RemediationMetrics[]> {
    const relevantTrackings = violationId
      ? this.trackings.filter(t => t.violationId === violationId)
      : this.trackings;

    // Group by violation pattern (for recurrence tracking)
    const violationGroups = new Map<string, RemediationTracking[]>();
    
    relevantTrackings.forEach(tracking => {
      const key = tracking.originalViolationId || tracking.violationId;
      if (!violationGroups.has(key)) {
        violationGroups.set(key, []);
      }
      violationGroups.get(key)!.push(tracking);
    });

    const metrics: RemediationMetrics[] = [];

    for (const [key, trackings] of violationGroups) {
      const completed = trackings.filter(t => t.status === 'completed' && t.timeToRemediation);
      const started = trackings.filter(t => t.startedAt && t.timeToStart);
      const effective = trackings.filter(t => t.effectiveness === 'effective');
      const recurred = trackings.filter(t => t.isRecurrence);

      const averageTimeToRemediation = completed.length > 0
        ? completed.reduce((sum, t) => sum + (t.timeToRemediation || 0), 0) / completed.length
        : 0;

      const averageTimeToStart = started.length > 0
        ? started.reduce((sum, t) => sum + (t.timeToStart || 0), 0) / started.length
        : 0;

      const effectivenessRate = trackings.length > 0
        ? (effective.length / trackings.length) * 100
        : 0;

      const recurrenceRate = trackings.length > 0
        ? (recurred.length / trackings.length) * 100
        : 0;

      metrics.push({
        violationId: key,
        averageTimeToRemediation,
        averageTimeToStart,
        effectivenessRate,
        recurrenceRate,
        totalRemediations: trackings.length,
        successfulRemediations: effective.length,
        failedRemediations: trackings.filter(t => t.effectiveness === 'ineffective').length,
      });
    }

    return metrics;
  }

  private async checkRecurrence(violationId: string, violation: any): Promise<boolean> {
    // Check if similar violations have been resolved before
    const similarTrackings = this.trackings.filter(t => {
      if (t.violationId === violationId) return false;
      // Check if same type, severity, and resource
      return this.isSameViolation(violation, t.violationId);
    });

    return similarTrackings.length > 0;
  }

  private async isSameViolation(violation: any, otherViolationId: string): Promise<boolean> {
    try {
      const otherViolation = await this.violationsService.findOne(otherViolationId);
      return (
        violation.type === otherViolation.type &&
        violation.severity === otherViolation.severity &&
        violation.resource === otherViolation.resource &&
        violation.policyId === otherViolation.policyId
      );
    } catch {
      return false;
    }
  }

  async addMilestone(id: string, milestone: Omit<RemediationMilestone, 'id'>): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    tracking.milestones.push({
      ...milestone,
      id: uuidv4(),
    });
    tracking.updatedAt = new Date();

    await this.saveTrackings();
    return tracking;
  }

  async updateMilestone(
    id: string,
    milestoneId: string,
    updates: Partial<RemediationMilestone>
  ): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    const milestone = tracking.milestones.find(m => m.id === milestoneId);
    if (!milestone) {
      throw new NotFoundException(`Milestone with ID ${milestoneId} not found`);
    }

    Object.assign(milestone, updates);
    tracking.updatedAt = new Date();

    await this.saveTrackings();
    return tracking;
  }

  async addStep(id: string, step: Omit<RemediationStep, 'id'>): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    tracking.remediationSteps.push({
      ...step,
      id: uuidv4(),
    });
    tracking.updatedAt = new Date();

    await this.saveTrackings();
    return tracking;
  }

  async updateStep(
    id: string,
    stepId: string,
    updates: Partial<RemediationStep>
  ): Promise<RemediationTracking> {
    const tracking = await this.findOneTracking(id);
    
    const step = tracking.remediationSteps.find(s => s.id === stepId);
    if (!step) {
      throw new NotFoundException(`Step with ID ${stepId} not found`);
    }

    const wasCompleted = step.status === 'completed';
    Object.assign(step, updates);

    if (updates.status === 'in-progress' && !step.startedAt) {
      step.startedAt = new Date();
    }

    if (updates.status === 'completed' && !wasCompleted) {
      step.completedAt = new Date();
      if (step.startedAt) {
        step.duration = (step.completedAt.getTime() - step.startedAt.getTime()) / (1000 * 60);
      }
    }

    tracking.updatedAt = new Date();

    await this.saveTrackings();
    return tracking;
  }
}

