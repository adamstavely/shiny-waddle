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
} from './entities/finding-approval.entity';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { NotificationsService } from '../notifications/notifications.service';
import { UsersService } from '../users/users.service';

@Injectable()
export class FindingApprovalsService {
  private readonly logger = new Logger(FindingApprovalsService.name);
  private readonly approvalsFile = path.join(process.cwd(), '..', '..', 'data', 'finding-approvals.json');
  private approvals: FindingApprovalRequest[] = [];

  constructor(
    @Inject(forwardRef(() => UnifiedFindingsService))
    private readonly findingsService: UnifiedFindingsService,
    @Inject(forwardRef(() => NotificationsService))
    private readonly notificationsService: NotificationsService,
    @Inject(forwardRef(() => UsersService))
    private readonly usersService: UsersService
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
    const finding = await this.findingsService.getFindingById(dto.findingId);
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

    // Determine required approvers
    const requiredApprovers = dto.requiredApprovers || 
      this.determineRequiredApprovers(finding.severity, dto.type);

    // Create approval entries for each required approver
    const approvals = requiredApprovers.map(role => ({
      approverId: '', // Will be set when approved
      approverRole: role,
      status: 'pending' as const,
    }));

    const request: FindingApprovalRequest = {
      id: uuidv4(),
      findingId: dto.findingId,
      type: dto.type,
      requestedBy: dto.requestedBy,
      requestedAt: new Date(),
      reason: dto.reason,
      status: 'pending',
      approvals,
      requiredApprovers,
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
      // Get all users with approver roles that match required approvers
      const approverUsers = await this.usersService.getUsersByRoles(request.requiredApprovers);
      
      if (approverUsers.length === 0) {
        this.logger.warn(
          `No approver users found for roles: ${request.requiredApprovers.join(', ')}`
        );
      } else {
        // Notify each approver user
        for (const approver of approverUsers) {
          try {
            // Check user's notification preferences
            const preferences = this.notificationsService.getUserPreferences(approver.id);
            
            if (preferences.enabled && preferences.notifyOnApprovalRequest) {
              await this.notificationsService.notifyApprovalRequest(
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
   * Approve a request
   */
  async approveRequest(
    requestId: string,
    dto: ApproveRequestDto
  ): Promise<FindingApprovalRequest> {
    const request = await this.getRequestById(requestId);

    if (request.status !== 'pending') {
      throw new BadRequestException('Request is not pending');
    }

    // Find the approval entry for this approver role
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
    // For OR logic (either approver can approve), if any approver approves, it's approved
    // For AND logic (both must approve), all must approve
    const allApproved = request.approvals
      .filter(a => request.requiredApprovers.includes(a.approverRole))
      .every(a => a.status === 'approved');

    // For OR logic: if any required approver approves, approve the request
    // For AND logic: all must approve
    // We'll use OR logic by default (first approval wins for single-approver, both must approve for critical)
    const isCritical = request.metadata?.findingSeverity === 'critical';
    const shouldApprove = isCritical ? allApproved : approval.status === 'approved';

    if (shouldApprove) {
      request.status = 'approved';
      
      // Update finding status
      const newStatus = request.type === 'risk-acceptance' ? 'risk-accepted' : 'false-positive';
      try {
        await this.findingsService.updateFinding(request.findingId, { status: newStatus });
      } catch (err) {
        // Log error but don't fail the approval - finding update can be retried
        this.logger.error('Failed to update finding status after approval:', err);
      }

      // Notify requester
      if (this.notificationsService) {
        try {
          await this.notificationsService.notifyApprovalStatusChanged(
            request.requestedBy,
            request.id,
            request.findingId,
            request.metadata?.findingTitle || 'Finding',
            'approved'
          );
        } catch (err) {
          // Log but don't fail - notification failures shouldn't break approval
          this.logger.error('Failed to send approval notification:', err);
        }
      }
    }

    await this.saveApprovals();
    return request;
  }

  /**
   * Reject a request
   */
  async rejectRequest(
    requestId: string,
    dto: RejectRequestDto
  ): Promise<FindingApprovalRequest> {
    const request = await this.getRequestById(requestId);

    if (request.status !== 'pending') {
      throw new BadRequestException('Request is not pending');
    }

    // Find the approval entry for this approver role
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

      // Notify requester
      if (this.notificationsService) {
        try {
          await this.notificationsService.notifyApprovalStatusChanged(
            request.requestedBy,
            request.id,
            request.findingId,
            request.metadata?.findingTitle || 'Finding',
            'rejected'
          );
        } catch (err) {
          // Log but don't fail - notification failures shouldn't break rejection
          this.logger.error('Failed to send rejection notification:', err);
        }
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

