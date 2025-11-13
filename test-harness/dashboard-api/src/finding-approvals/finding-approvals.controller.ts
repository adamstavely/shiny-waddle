import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Body,
  Query,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { FindingApprovalsService } from './finding-approvals.service';
import {
  CreateApprovalRequestDto,
  ApproveRequestDto,
  RejectRequestDto,
  ApproverRole,
} from './entities/finding-approval.entity';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { UserContext } from '../common/interfaces/user-context.interface';

@Controller('api/finding-approvals')
export class FindingApprovalsController {
  constructor(private readonly approvalsService: FindingApprovalsService) {}

  @Post('request')
  async createRequest(
    @CurrentUser() user: UserContext,
    @Body() dto: CreateApprovalRequestDto,
  ) {
    // Set requestedBy from user context
    dto.requestedBy = user.id;
    return this.approvalsService.createRequest(dto);
  }

  @Get('pending')
  async getPendingApprovals(
    @CurrentUser() user: UserContext,
    @Query('approverRole') approverRole?: ApproverRole,
  ) {
    // Auto-detect approver role from user context
    let detectedRole: ApproverRole | undefined = approverRole;
    if (!detectedRole) {
      if (user.roles.includes('cyber-risk-manager')) {
        detectedRole = 'cyber-risk-manager';
      } else if (user.roles.includes('data-steward')) {
        detectedRole = 'data-steward';
      }
    }
    
    if (!detectedRole) {
      throw new HttpException('User does not have approver role', HttpStatus.FORBIDDEN);
    }
    
    return this.approvalsService.getPendingApprovals(detectedRole, user.id);
  }

  @Get('finding/:findingId')
  async getRequestByFinding(@Param('findingId') findingId: string) {
    return this.approvalsService.getRequestByFindingId(findingId);
  }

  @Get('user')
  async getRequestsByUser(@CurrentUser() user: UserContext) {
    return this.approvalsService.getRequestsByUser(user.id);
  }

  @Get(':id')
  async getRequest(@Param('id') id: string) {
    return this.approvalsService.getRequestById(id);
  }

  @Patch(':id/approve')
  async approveRequest(
    @Param('id') id: string,
    @CurrentUser() user: UserContext,
    @Body() dto: ApproveRequestDto,
  ) {
    // Auto-detect approver role from user context
    if (!dto.approverRole) {
      if (user.roles.includes('cyber-risk-manager')) {
        dto.approverRole = 'cyber-risk-manager';
      } else if (user.roles.includes('data-steward')) {
        dto.approverRole = 'data-steward';
      } else {
        throw new HttpException('User does not have approver role', HttpStatus.FORBIDDEN);
      }
    }
    dto.approverId = user.id;
    return this.approvalsService.approveRequest(id, dto);
  }

  @Patch(':id/reject')
  async rejectRequest(
    @Param('id') id: string,
    @CurrentUser() user: UserContext,
    @Body() dto: RejectRequestDto,
  ) {
    // Auto-detect approver role from user context
    if (!dto.approverRole) {
      if (user.roles.includes('cyber-risk-manager')) {
        dto.approverRole = 'cyber-risk-manager';
      } else if (user.roles.includes('data-steward')) {
        dto.approverRole = 'data-steward';
      } else {
        throw new HttpException('User does not have approver role', HttpStatus.FORBIDDEN);
      }
    }
    dto.approverId = user.id;
    return this.approvalsService.rejectRequest(id, dto);
  }

  @Patch(':id/cancel')
  async cancelRequest(
    @Param('id') id: string,
    @CurrentUser() user: UserContext,
  ) {
    return this.approvalsService.cancelRequest(id, user.id);
  }
}

