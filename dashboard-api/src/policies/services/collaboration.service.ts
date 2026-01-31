import { Injectable, Logger } from '@nestjs/common';
import { PoliciesService } from '../policies.service';

export interface PolicyComment {
  id: string;
  policyId: string;
  userId: string;
  userName: string;
  content: string;
  createdAt: Date;
  updatedAt?: Date;
  parentId?: string; // For threaded comments
  mentions?: string[]; // User IDs mentioned
}

export interface PolicyApproval {
  id: string;
  policyId: string;
  requestedBy: string;
  requestedAt: Date;
  stages: ApprovalStage[];
  status: 'pending' | 'approved' | 'rejected' | 'cancelled';
  currentStage: number;
  approvedAt?: Date;
  rejectedAt?: Date;
  rejectedBy?: string;
  rejectionReason?: string;
}

export interface ApprovalStage {
  stageNumber: number;
  approvers: string[];
  requiredApprovals: number;
  approvals: Array<{
    approverId: string;
    approvedAt: Date;
    comments?: string;
  }>;
  rejections: Array<{
    approverId: string;
    rejectedAt: Date;
    reason: string;
  }>;
  status: 'pending' | 'approved' | 'rejected';
}

@Injectable()
export class CollaborationService {
  private readonly logger = new Logger(CollaborationService.name);
  private readonly comments: Map<string, PolicyComment> = new Map();
  private readonly approvals: Map<string, PolicyApproval> = new Map();

  constructor(
    private readonly policiesService: PoliciesService,
  ) {}

  /**
   * Add a comment to a policy
   */
  async addComment(
    policyId: string,
    userId: string,
    userName: string,
    content: string,
    parentId?: string,
  ): Promise<PolicyComment> {
    // Verify policy exists
    const policy = await this.policiesService.findOne(policyId);
    if (!policy) {
      throw new Error(`Policy ${policyId} not found`);
    }

    const comment: PolicyComment = {
      id: `comment-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      policyId,
      userId,
      userName,
      content,
      createdAt: new Date(),
      parentId,
      mentions: this.extractMentions(content),
    };

    this.comments.set(comment.id, comment);
    this.logger.log(`Added comment ${comment.id} to policy ${policyId}`);

    return comment;
  }

  /**
   * Get comments for a policy
   */
  async getComments(policyId: string): Promise<PolicyComment[]> {
    const allComments = Array.from(this.comments.values());
    return allComments
      .filter(c => c.policyId === policyId)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  }

  /**
   * Update a comment
   */
  async updateComment(
    commentId: string,
    userId: string,
    content: string,
  ): Promise<PolicyComment> {
    const comment = this.comments.get(commentId);
    if (!comment) {
      throw new Error(`Comment ${commentId} not found`);
    }

    if (comment.userId !== userId) {
      throw new Error('Only the comment author can update the comment');
    }

    comment.content = content;
    comment.updatedAt = new Date();
    comment.mentions = this.extractMentions(content);

    this.comments.set(commentId, comment);
    return comment;
  }

  /**
   * Delete a comment
   */
  async deleteComment(commentId: string, userId: string): Promise<void> {
    const comment = this.comments.get(commentId);
    if (!comment) {
      throw new Error(`Comment ${commentId} not found`);
    }

    if (comment.userId !== userId) {
      throw new Error('Only the comment author can delete the comment');
    }

    this.comments.delete(commentId);
    this.logger.log(`Deleted comment ${commentId}`);
  }

  /**
   * Create an approval request for a policy
   */
  async createApprovalRequest(
    policyId: string,
    requestedBy: string,
    stages: Omit<ApprovalStage, 'status' | 'approvals' | 'rejections'>[],
  ): Promise<PolicyApproval> {
    // Verify policy exists
    const policy = await this.policiesService.findOne(policyId);
    if (!policy) {
      throw new Error(`Policy ${policyId} not found`);
    }

    const approval: PolicyApproval = {
      id: `approval-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      policyId,
      requestedBy,
      requestedAt: new Date(),
      stages: stages.map((stage, index) => ({
        ...stage,
        stageNumber: index + 1,
        approvals: [],
        rejections: [],
        status: index === 0 ? 'pending' : 'pending',
      })),
      status: 'pending',
      currentStage: 1,
    };

    this.approvals.set(approval.id, approval);
    this.logger.log(`Created approval request ${approval.id} for policy ${policyId}`);

    return approval;
  }

  /**
   * Approve a policy at current stage
   */
  async approve(
    approvalId: string,
    approverId: string,
    comments?: string,
  ): Promise<PolicyApproval> {
    const approval = this.approvals.get(approvalId);
    if (!approval) {
      throw new Error(`Approval ${approvalId} not found`);
    }

    if (approval.status !== 'pending') {
      throw new Error(`Approval ${approvalId} is not pending`);
    }

    const currentStage = approval.stages[approval.currentStage - 1];
    if (!currentStage) {
      throw new Error(`Invalid stage ${approval.currentStage}`);
    }

    // Check if approver is authorized
    if (!currentStage.approvers.includes(approverId)) {
      throw new Error(`User ${approverId} is not authorized to approve at this stage`);
    }

    // Check if already approved by this approver
    if (currentStage.approvals.some(a => a.approverId === approverId)) {
      throw new Error('You have already approved this stage');
    }

    // Add approval
    currentStage.approvals.push({
      approverId,
      approvedAt: new Date(),
      comments,
    });

    // Check if stage is complete
    if (currentStage.approvals.length >= currentStage.requiredApprovals) {
      currentStage.status = 'approved';

      // Move to next stage or complete approval
      if (approval.currentStage < approval.stages.length) {
        approval.currentStage++;
        approval.stages[approval.currentStage - 1].status = 'pending';
      } else {
        // All stages approved
        approval.status = 'approved';
        approval.approvedAt = new Date();
      }
    }

    this.approvals.set(approvalId, approval);
    this.logger.log(`Approval ${approvalId} updated: stage ${approval.currentStage}`);

    return approval;
  }

  /**
   * Reject a policy approval
   */
  async reject(
    approvalId: string,
    approverId: string,
    reason: string,
  ): Promise<PolicyApproval> {
    const approval = this.approvals.get(approvalId);
    if (!approval) {
      throw new Error(`Approval ${approvalId} not found`);
    }

    if (approval.status !== 'pending') {
      throw new Error(`Approval ${approvalId} is not pending`);
    }

    const currentStage = approval.stages[approval.currentStage - 1];
    if (!currentStage) {
      throw new Error(`Invalid stage ${approval.currentStage}`);
    }

    // Check if approver is authorized
    if (!currentStage.approvers.includes(approverId)) {
      throw new Error(`User ${approverId} is not authorized to reject at this stage`);
    }

    // Add rejection
    currentStage.rejections.push({
      approverId,
      rejectedAt: new Date(),
      reason,
    });

    // Reject the entire approval
    currentStage.status = 'rejected';
    approval.status = 'rejected';
    approval.rejectedAt = new Date();
    approval.rejectedBy = approverId;
    approval.rejectionReason = reason;

    this.approvals.set(approvalId, approval);
    this.logger.log(`Approval ${approvalId} rejected by ${approverId}`);

    return approval;
  }

  /**
   * Get approval requests for a policy
   */
  async getApprovals(policyId: string): Promise<PolicyApproval[]> {
    const allApprovals = Array.from(this.approvals.values());
    return allApprovals
      .filter(a => a.policyId === policyId)
      .sort((a, b) => b.requestedAt.getTime() - a.requestedAt.getTime());
  }

  /**
   * Get a specific approval
   */
  async getApproval(approvalId: string): Promise<PolicyApproval | null> {
    return this.approvals.get(approvalId) || null;
  }

  /**
   * Extract mentions from comment content
   */
  private extractMentions(content: string): string[] {
    const mentionRegex = /@(\w+)/g;
    const mentions: string[] = [];
    let match;

    while ((match = mentionRegex.exec(content)) !== null) {
      mentions.push(match[1]);
    }

    return mentions;
  }
}
