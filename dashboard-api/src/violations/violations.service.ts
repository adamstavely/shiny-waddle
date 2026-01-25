import { Injectable, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { CreateViolationDto, ViolationStatus } from './dto/create-violation.dto';
import { UpdateViolationDto } from './dto/update-violation.dto';
import { ViolationEntity, ViolationComment, RemediationEvent } from './entities/violation.entity';
import { AppLogger } from '../common/services/logger.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ViolationsService {
  private readonly violationsFile = path.join(process.cwd(), '..', 'data', 'violations.json');
  private violations: ViolationEntity[] = [];
  private readonly logger = new AppLogger(ViolationsService.name);

  constructor() {
    this.loadViolations().catch(err => {
      this.logger.error('Error loading violations on startup', err.stack);
    });
  }

  private async loadViolations(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.violationsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.violationsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.violations = (Array.isArray(parsed) ? parsed : []).map((v: any) => ({
          ...v,
          detectedAt: new Date(v.detectedAt),
          resolvedAt: v.resolvedAt ? new Date(v.resolvedAt) : undefined,
          ignoredAt: v.ignoredAt ? new Date(v.ignoredAt) : undefined,
          createdAt: new Date(v.createdAt),
          updatedAt: new Date(v.updatedAt),
          comments: (v.comments || []).map((c: any) => ({
            ...c,
            createdAt: new Date(c.createdAt),
            updatedAt: c.updatedAt ? new Date(c.updatedAt) : undefined,
          })),
          remediationTimeline: (v.remediationTimeline || []).map((e: any) => ({
            ...e,
            timestamp: new Date(e.timestamp),
          })),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.violations = [];
          await this.saveViolations();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading violations', error instanceof Error ? error.stack : String(error));
      this.violations = [];
    }
  }

  private async saveViolations() {
    try {
      await fs.mkdir(path.dirname(this.violationsFile), { recursive: true });
      await fs.writeFile(
        this.violationsFile,
        JSON.stringify(this.violations, null, 2),
        'utf-8',
      );
    } catch (error) {
      this.logger.error('Error saving violations', error instanceof Error ? error.stack : String(error));
      throw error;
    }
  }

  async create(createViolationDto: CreateViolationDto): Promise<ViolationEntity> {
    const violation: ViolationEntity = {
      id: uuidv4(),
      title: createViolationDto.title,
      description: createViolationDto.description,
      type: createViolationDto.type,
      severity: createViolationDto.severity,
      status: createViolationDto.status || ViolationStatus.OPEN,
      application: createViolationDto.application,
      team: createViolationDto.team,
      policyName: createViolationDto.policyName,
      policyId: createViolationDto.policyId,
      resource: createViolationDto.resource,
      affectedResources: createViolationDto.affectedResources || [],
      testResultId: createViolationDto.testResultId,
      testResultDetails: createViolationDto.testResultDetails,
      remediationSuggestions: createViolationDto.remediationSuggestions || [],
      remediationStatus: undefined,
      remediationTimeline: [],
      verificationTestIds: [],
      comments: [],
      detectedAt: createViolationDto.detectedAt || new Date(),
      assignedTo: createViolationDto.assignedTo,
      relatedViolationIds: createViolationDto.relatedViolationIds || [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.violations.push(violation);
    await this.saveViolations();

    // Trigger automated remediation (if remediation service is available)
    // This will be handled via event or direct call if module is imported

    return violation;
  }

  async findAll(
    severity?: string,
    type?: string,
    status?: string,
    application?: string,
    team?: string,
  ): Promise<ViolationEntity[]> {
    let filtered = [...this.violations];

    if (severity) {
      filtered = filtered.filter(v => v.severity === severity);
    }
    if (type) {
      filtered = filtered.filter(v => v.type === type);
    }
    if (status) {
      filtered = filtered.filter(v => v.status === status);
    }
    if (application) {
      filtered = filtered.filter(v => v.application === application);
    }
    if (team) {
      filtered = filtered.filter(v => v.team === team);
    }

    return filtered;
  }

  async findOne(id: string): Promise<ViolationEntity> {
    const violation = this.violations.find(v => v.id === id);
    if (!violation) {
      throw new NotFoundException(`Violation with ID "${id}" not found`);
    }
    return violation;
  }

  async update(id: string, updateViolationDto: UpdateViolationDto): Promise<ViolationEntity> {
    const index = this.violations.findIndex(v => v.id === id);
    if (index === -1) {
      throw new NotFoundException(`Violation with ID "${id}" not found`);
    }

    const violation = this.violations[index];
    const now = new Date();

    // Track status changes in remediation timeline
    if (updateViolationDto.status && updateViolationDto.status !== violation.status) {
      if (!violation.remediationTimeline) {
        violation.remediationTimeline = [];
      }
      violation.remediationTimeline.push({
        id: uuidv4(),
        type: 'status-change',
        description: `Status changed from ${violation.status} to ${updateViolationDto.status}`,
        actor: updateViolationDto.resolvedBy || updateViolationDto.ignoredBy || 'system',
        timestamp: now,
      });
    }

    this.violations[index] = {
      ...violation,
      ...updateViolationDto,
      updatedAt: now,
    };

    await this.saveViolations();

    return this.violations[index];
  }

  async remove(id: string): Promise<void> {
    const index = this.violations.findIndex(v => v.id === id);
    if (index === -1) {
      throw new NotFoundException(`Violation with ID "${id}" not found`);
    }

    this.violations.splice(index, 1);
    await this.saveViolations();
  }

  async addComment(id: string, author: string, content: string): Promise<ViolationComment> {
    const violation = await this.findOne(id);
    
    if (!violation.comments) {
      violation.comments = [];
    }

    const comment: ViolationComment = {
      id: uuidv4(),
      author,
      content,
      createdAt: new Date(),
    };

    violation.comments.push(comment);
    violation.updatedAt = new Date();

    // Add to remediation timeline
    if (!violation.remediationTimeline) {
      violation.remediationTimeline = [];
    }
    violation.remediationTimeline.push({
      id: uuidv4(),
      type: 'comment',
      description: `Comment added by ${author}`,
      actor: author,
      timestamp: new Date(),
      metadata: { commentId: comment.id },
    });

    await this.saveViolations();

    return comment;
  }

  async updateComment(
    violationId: string,
    commentId: string,
    content: string,
  ): Promise<ViolationComment> {
    const violation = await this.findOne(violationId);
    
    if (!violation.comments) {
      throw new NotFoundException('Comment not found');
    }

    const commentIndex = violation.comments.findIndex(c => c.id === commentId);
    if (commentIndex === -1) {
      throw new NotFoundException('Comment not found');
    }

    violation.comments[commentIndex] = {
      ...violation.comments[commentIndex],
      content,
      updatedAt: new Date(),
    };

    violation.updatedAt = new Date();
    await this.saveViolations();

    return violation.comments[commentIndex];
  }

  async deleteComment(violationId: string, commentId: string): Promise<void> {
    const violation = await this.findOne(violationId);
    
    if (!violation.comments) {
      throw new NotFoundException('Comment not found');
    }

    const commentIndex = violation.comments.findIndex(c => c.id === commentId);
    if (commentIndex === -1) {
      throw new NotFoundException('Comment not found');
    }

    violation.comments.splice(commentIndex, 1);
    violation.updatedAt = new Date();
    await this.saveViolations();
  }
}

