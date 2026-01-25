import { Injectable, NotFoundException, BadRequestException, Inject, forwardRef, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  FindingApprovalRequest,
  CreateApprovalRequestDto,
  ApproveRequestDto,
  RejectRequestDto,
  ApprovalRequestStatus,
  ApproverRole,
  ApprovalStage,
} from './entities/finding-approval.entity';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { NotificationsService } from '../notifications/notifications.service';
import { UsersService } from '../users/users.service';

@Injectable()
export class FindingApprovalsService {
  private readonly logger = new Logger(FindingApprovalsService.name);
  private readonly approvalsFile = path.join(process.cwd(), '..', 'data', 'finding-approvals.json');
  private approvals: FindingApprovalRequest[] = [];

  constructor(
    private readonly moduleRef: ModuleRef,
  ) {
    this.loadData().catch(err => {
      this.logger.error('Error loading approval data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.approvalsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.approvalsFile, 'utf-8');
        if (data && data.trim()) {
          this.approvals = JSON.parse(data).map((a: any) => ({
            ...a,
            requestedAt: new Date(a.requestedAt),
            expiresAt: a.expiresAt ? new Date(a.expiresAt) : undefined,
            approvals: a.approvals.map((app: any) => ({
              ...app,
              approvedAt: app.approvedAt ? new Date(app.approvedAt) : undefined,
            })),
          }));
        }
      } catch {
        this.approvals = [];
      }
    } catch (error) {
      this.logger.error('Error loading approval data:', error);
    }
  }

  private async saveApprovals(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.approvalsFile), { recursive: true });
      await fs.writeFile(
        this.approvalsFile,
        JSON.stringify(this.approvals, null, 2),
        'utf-8'
      );
    } catch (error) {
      this.logger.error('Error saving approvals:', error);
      throw error;
    }
  }

  /**
   * Determine required approvers based on finding severity and type
   */
  private determineRequiredApprovers(
    findingSeverity: string,
    requestType: 'risk-acceptance' | 'false-positive'
  ): ApproverRole[] {
    // For critical findings, require both approvers
    if (findingSeverity === 'critical') {
      return ['cyber-risk-manager', 'data-steward'];
    }

    // For high severity, require cyber-risk-manager
    if (findingSeverity === 'high') {
      return ['cyber-risk-manager'];
    }

    // For other severities, either approver is sufficient
    // Default to cyber-risk-manager, but data-steward can also approve
    return ['cyber-risk-manager'];
  }

  /**
   * Create an approval request
   */
  async createRequest(dto: CreateApprovalRequestDto): Promise<FindingApprovalRequest> {
    // Check if finding exists
    const findingsService = this.moduleRef.get(UnifiedFindingsService, { strict: false });
    if (!findingsService) {
      throw new Error('UnifiedFindingsService not available');
    }
    const finding = await findingsService.getFindingById(dto.findingId);
    if (!finding) {
      throw new NotFoundException('Finding not found');
    }

    // Check if there's already a pending request for this finding
    const existingRequest = this.approvals.find(
      a => a.findingId === dto.findingId && a.status === 'pending'
    );
    if (existingRequest) {
      throw new BadRequestException('A pending approval request already exists for this finding');
    }

    // Determine required approvers (for legacy support)
    const requiredApprovers = dto.requiredApprovers || 
      this.determineRequiredApprovers(finding.severity, dto.type);

    // Create approval entries for each required approver (legacy)
    const approvals = requiredApprovers.map(role => ({
      approverId: '', // Will be set when approved
      approverRole: role,
      status: 'pending' as const,
    }));

    // Create multi-stage workflow if stages are provided
    let stages: ApprovalStage[] | undefined;
    let currentStageId: string | undefined;

    if (dto.stages && dto.stages.length > 0) {
      stages = dto.stages.map((stageConfig, index) => {
        const stageId = `stage-${index + 1}`;
        return {
          stageId,
          stageName: stageConfig.stageName,
          order: index + 1,
          requiredApprovers: stageConfig.requiredApprovers,
          approvals: stageConfig.requiredApprovers.map(role => ({
            approverId: '',
            approverRole: role,
            status: 'pending' as const,
          })),
          status: index === 0 ? 'in-progress' : 'pending',
          workflowType: stageConfig.workflowType,
          conditions: stageConfig.conditions,
          minApprovals: stageConfig.minApprovals,
        };
      });
      currentStageId = stages[0].stageId;
    }

    const request: FindingApprovalRequest = {
      id: uuidv4(),
      findingId: dto.findingId,
      type: dto.type,
      requestedBy: dto.requestedBy,
      requestedAt: new Date(),
      reason: dto.reason,
      status: 'pending',
      approvals, // Legacy support
      requiredApprovers, // Legacy support
      stages, // New multi-stage workflow
      currentStageId,
      expiresAt: dto.expiresAt,
      metadata: {
        applicationId: finding.asset.applicationId,
        findingTitle: finding.title,
        findingSeverity: finding.severity,
      },
    };

    this.approvals.push(request);
    await this.saveApprovals();

    // Notify approvers
    try {
      const usersService = this.moduleRef.get(UsersService, { strict: false });
      const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
      
      if (!usersService || !notificationsService) {
        this.logger.warn('UsersService or NotificationsService not available for notifications');
        return;
      }
      
      // Get all users with approver roles that match required approvers
      const approverUsers = await usersService.getUsersByRoles(request.requiredApprovers);
      
      if (approverUsers.length === 0) {
        this.logger.warn(
          `No approver users found for roles: ${request.requiredApprovers.join(', ')}`
        );
      } else {
        // Notify each approver user
        for (const approver of approverUsers) {
          try {
            // Check user's notification preferences
            const preferences = notificationsService.getUserPreferences(approver.id);
            
            if (preferences.enabled && preferences.notifyOnApprovalRequest) {
              await notificationsService.notifyApprovalRequest(
                approver.id,
                request.id,
                request.findingId,
                request.metadata?.findingTitle || 'Finding',
                request.type
              );
            }
          } catch (err) {
            this.logger.error(
              `Failed to notify approver ${approver.id} about approval request:`,
              err
            );
            // Don't throw - notification failures shouldn't break request creation
          }
        }
      }
    } catch (err) {
      this.logger.error('Error notifying approvers about new request:', err);
      // Don't throw - notification failures shouldn't break request creation
    }

    return request;
  }

  /**
   * Get approval request by ID
   */
  async getRequestById(id: string): Promise<FindingApprovalRequest> {
    const request = this.approvals.find(a => a.id === id);
    if (!request) {
      throw new NotFoundException('Approval request not found');
    }
    return request;
  }

  /**
   * Get approval request for a finding
   */
  async getRequestByFindingId(findingId: string): Promise<FindingApprovalRequest | null> {
    return this.approvals.find(a => a.findingId === findingId) || null;
  }

  /**
   * Get pending approvals for a user (by role)
   */
  async getPendingApprovals(approverRole: ApproverRole, approverId?: string): Promise<FindingApprovalRequest[]> {
    return this.approvals.filter(a => {
      if (a.status !== 'pending') return false;
      
      // Check if this approver role is required
      const hasRole = a.requiredApprovers.includes(approverRole);
      if (!hasRole) return false;

      // Check if this approver hasn't already approved/rejected
      const approverApproval = a.approvals.find(app => app.approverRole === approverRole);
      if (approverApproval && approverApproval.status !== 'pending') return false;

      // If approverId is provided, check if it matches
      if (approverId && approverApproval && approverApproval.approverId && approverApproval.approverId !== approverId) {
        return false;
      }

      // Check expiration
      if (a.expiresAt && new Date() > a.expiresAt) {
        return false;
      }

      return true;
    });
  }

  /**
   * Approve a request (supports both legacy and multi-stage workflows)
   */
  async approveRequest(
    requestId: string,
    dto: ApproveRequestDto
  ): Promise<FindingApprovalRequest> {
    const request = await this.getRequestById(requestId);

    if (request.status !== 'pending') {
      throw new BadRequestException('Request is not pending');
    }

    // Handle multi-stage workflow
    if (request.stages && request.stages.length > 0) {
      return this.approveMultiStageRequest(request, dto);
    }

    // Legacy single-stage workflow
    const approval = request.approvals.find(a => a.approverRole === dto.approverRole);
    if (!approval) {
      throw new BadRequestException('Approver role not found in request');
    }

    if (approval.status !== 'pending') {
      throw new BadRequestException('Approval already processed');
    }

    // Update approval
    approval.status = 'approved';
    approval.approverId = dto.approverId;
    approval.approvedAt = new Date();
    if (dto.comment) {
      approval.comment = dto.comment;
    }

    // Check if all required approvers have approved
    const allApproved = request.approvals
      .filter(a => request.requiredApprovers.includes(a.approverRole))
      .every(a => a.status === 'approved');

    const isCritical = request.metadata?.findingSeverity === 'critical';
    const shouldApprove = isCritical ? allApproved : approval.status === 'approved';

    if (shouldApprove) {
      request.status = 'approved';
      await this.finalizeApproval(request);
    }

    await this.saveApprovals();
    return request;
  }

  /**
   * Approve a multi-stage workflow request
   */
  private async approveMultiStageRequest(
    request: FindingApprovalRequest,
    dto: ApproveRequestDto
  ): Promise<FindingApprovalRequest> {
    if (!request.currentStageId || !request.stages) {
      throw new BadRequestException('Invalid multi-stage workflow');
    }

    const currentStage = request.stages.find(s => s.stageId === request.currentStageId);
    if (!currentStage) {
      throw new BadRequestException('Current stage not found');
    }

    if (currentStage.status !== 'in-progress' && currentStage.status !== 'pending') {
      throw new BadRequestException('Current stage is not active');
    }

    // Find approval in current stage
    const approval = currentStage.approvals.find(a => a.approverRole === dto.approverRole);
    if (!approval) {
      throw new BadRequestException('Approver role not found in current stage');
    }

    if (approval.status !== 'pending') {
      throw new BadRequestException('Approval already processed in this stage');
    }

    // Update approval
    approval.status = 'approved';
    approval.approverId = dto.approverId;
    approval.approvedAt = new Date();
    if (dto.comment) {
      approval.comment = dto.comment;
    }

    // Check stage completion based on workflow type
    const stageComplete = this.checkStageCompletion(currentStage);

    if (stageComplete) {
      currentStage.status = 'approved';

      // Check conditional routing
      const nextStageId = this.evaluateConditionalRouting(request, currentStage);
      
      if (nextStageId) {
        // Route to next stage (could be conditional or sequential)
        const nextStage = request.stages!.find(s => s.stageId === nextStageId);
        if (nextStage) {
          nextStage.status = 'in-progress';
          request.currentStageId = nextStageId;
        }
      } else {
        // Move to next sequential stage
        const nextSequentialStage = request.stages!.find(
          s => s.order === currentStage.order + 1
        );

        if (nextSequentialStage) {
          nextSequentialStage.status = 'in-progress';
          request.currentStageId = nextSequentialStage.stageId;
        } else {
          // All stages complete - approve the request
          request.status = 'approved';
          await this.finalizeApproval(request);
        }
      }
    }

    await this.saveApprovals();
    return request;
  }

  /**
   * Check if a stage is complete based on workflow type
   */
  private checkStageCompletion(stage: ApprovalStage): boolean {
    switch (stage.workflowType) {
      case 'parallel':
        // Parallel: need minimum approvals (or all if minApprovals not specified)
        const minApprovals = stage.minApprovals || stage.requiredApprovers.length;
        const approvedCount = stage.approvals.filter(a => a.status === 'approved').length;
        return approvedCount >= minApprovals;

      case 'sequential':
        // Sequential: all approvers must approve in order
        // For simplicity, we'll require all to approve
        return stage.approvals.every(a => a.status === 'approved');

      case 'conditional':
        // Conditional: evaluate conditions to determine completion
        // For now, treat as parallel
        const conditionalMin = stage.minApprovals || stage.requiredApprovers.length;
        const conditionalApproved = stage.approvals.filter(a => a.status === 'approved').length;
        return conditionalApproved >= conditionalMin;

      default:
        // Default: all must approve
        return stage.approvals.every(a => a.status === 'approved');
    }
  }

  /**
   * Evaluate conditional routing
   */
  private evaluateConditionalRouting(
    request: FindingApprovalRequest,
    currentStage: ApprovalStage
  ): string | null {
    if (!currentStage.conditions || currentStage.conditions.length === 0) {
      return null;
    }

    // Evaluate conditions against request metadata
    for (const condition of currentStage.conditions) {
      const fieldValue = this.getFieldValue(request, condition.field);
      const conditionMet = this.evaluateCondition(fieldValue, condition.operator, condition.value);

      if (conditionMet && condition.nextStageId) {
        return condition.nextStageId;
      }
    }

    return null;
  }

  /**
   * Get field value from request (supports nested fields)
   */
  private getFieldValue(request: FindingApprovalRequest, field: string): any {
    const parts = field.split('.');
    let value: any = request;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Evaluate a condition
   */
  private evaluateCondition(fieldValue: any, operator: string, conditionValue: any): boolean {
    if (fieldValue === undefined || fieldValue === null) {
      return false;
    }

    switch (operator) {
      case 'equals':
        return fieldValue === conditionValue;
      case 'greaterThan':
        return fieldValue > conditionValue;
      case 'lessThan':
        return fieldValue < conditionValue;
      case 'contains':
        return String(fieldValue).toLowerCase().includes(String(conditionValue).toLowerCase());
      default:
        return false;
    }
  }

  /**
   * Finalize approval (update finding, send notifications)
   */
  private async finalizeApproval(request: FindingApprovalRequest): Promise<void> {
    // Update finding status
    const newStatus = request.type === 'risk-acceptance' ? 'risk-accepted' : 'false-positive';
    try {
      const findingsService = this.moduleRef.get(UnifiedFindingsService, { strict: false });
      if (findingsService) {
        await findingsService.updateFinding(request.findingId, { status: newStatus });
      }
    } catch (err) {
      this.logger.error('Failed to update finding status after approval:', err);
    }

    // Notify requester
    try {
      const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
      if (notificationsService) {
        await notificationsService.notifyApprovalStatusChanged(
          request.requestedBy,
          request.id,
          request.findingId,
          request.metadata?.findingTitle || 'Finding',
          'approved'
        );
      }
    } catch (err) {
      this.logger.error('Failed to send approval notification:', err);
    }
  }

  /**
   * Reject a request (supports both legacy and multi-stage workflows)
   */
  async rejectRequest(
    requestId: string,
    dto: RejectRequestDto
  ): Promise<FindingApprovalRequest> {
    const request = await this.getRequestById(requestId);

    if (request.status !== 'pending') {
      throw new BadRequestException('Request is not pending');
    }

    // Handle multi-stage workflow
    if (request.stages && request.stages.length > 0) {
      if (!request.currentStageId) {
        throw new BadRequestException('Invalid multi-stage workflow');
      }

      const currentStage = request.stages.find(s => s.stageId === request.currentStageId);
      if (!currentStage) {
        throw new BadRequestException('Current stage not found');
      }

      const approval = currentStage.approvals.find(a => a.approverRole === dto.approverRole);
      if (!approval) {
        throw new BadRequestException('Approver role not found in current stage');
      }

      if (approval.status !== 'pending') {
        throw new BadRequestException('Approval already processed in this stage');
      }

      // Update approval
      approval.status = 'rejected';
      approval.approverId = dto.approverId;
      approval.approvedAt = new Date();
      approval.comment = dto.comment;

      // Reject the stage and the whole request
      currentStage.status = 'rejected';
      request.status = 'rejected';
    } else {
      // Legacy workflow
      const approval = request.approvals.find(a => a.approverRole === dto.approverRole);
      if (!approval) {
        throw new BadRequestException('Approver role not found in request');
      }

      if (approval.status !== 'pending') {
        throw new BadRequestException('Approval already processed');
      }

      // Update approval
      approval.status = 'rejected';
      approval.approverId = dto.approverId;
      approval.approvedAt = new Date();
      approval.comment = dto.comment;

      // Reject the request (any rejection rejects the whole request)
      request.status = 'rejected';
    }

    // Notify requester
    try {
      const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
      if (notificationsService) {
        await notificationsService.notifyApprovalStatusChanged(
          request.requestedBy,
          request.id,
          request.findingId,
          request.metadata?.findingTitle || 'Finding',
          'rejected'
        );
      }
    } catch (err) {
      this.logger.error('Failed to send rejection notification:', err);
    }

    await this.saveApprovals();
    return request;
  }

  /**
   * Cancel a request
   */
  async cancelRequest(requestId: string, userId: string): Promise<FindingApprovalRequest> {
    const request = await this.getRequestById(requestId);

    if (request.requestedBy !== userId) {
      throw new BadRequestException('Only the requester can cancel the request');
    }

    if (request.status !== 'pending') {
      throw new BadRequestException('Only pending requests can be cancelled');
    }

    request.status = 'cancelled';
    await this.saveApprovals();
    return request;
  }

  /**
   * Get all requests for a user (as requester)
   */
  async getRequestsByUser(userId: string): Promise<FindingApprovalRequest[]> {
    return this.approvals.filter(a => a.requestedBy === userId);
  }
}

