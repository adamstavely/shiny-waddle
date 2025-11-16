import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Query,
} from '@nestjs/common';
import { RemediationTrackingService } from './remediation-tracking.service';
import { RemediationAutomationService } from './services/remediation-automation.service';
import {
  RemediationTracking,
  CreateRemediationTrackingDto,
  RemediationMetrics,
} from './entities/remediation-tracking.entity';

@Controller('api/v1/remediation-tracking')
export class RemediationTrackingController {
  constructor(
    private readonly trackingService: RemediationTrackingService,
    private readonly automationService: RemediationAutomationService,
  ) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createTracking(
    @Body(ValidationPipe) dto: CreateRemediationTrackingDto
  ): Promise<RemediationTracking> {
    return this.trackingService.createTracking(dto);
  }

  @Get()
  async findAllTrackings(@Query('violationId') violationId?: string): Promise<RemediationTracking[]> {
    return this.trackingService.findAllTrackings(violationId);
  }

  @Get(':id')
  async findOneTracking(@Param('id') id: string): Promise<RemediationTracking> {
    return this.trackingService.findOneTracking(id);
  }

  @Get('violation/:violationId')
  async findByViolationId(@Param('violationId') violationId: string): Promise<RemediationTracking | null> {
    return this.trackingService.findByViolationId(violationId);
  }

  @Post(':id/start')
  async startRemediation(
    @Param('id') id: string,
    @Body() body: { actor: string }
  ): Promise<RemediationTracking> {
    return this.trackingService.startRemediation(id, body.actor);
  }

  @Patch(':id/progress')
  async updateProgress(
    @Param('id') id: string,
    @Body() body: { progress: number; currentStep?: string; milestoneId?: string }
  ): Promise<RemediationTracking> {
    return this.trackingService.updateProgress(id, body.progress, body.currentStep, body.milestoneId);
  }

  @Post(':id/complete')
  async completeRemediation(
    @Param('id') id: string,
    @Body() body: {
      actor: string;
      effectiveness?: 'effective' | 'ineffective' | 'unknown';
      effectivenessReason?: string;
    }
  ): Promise<RemediationTracking> {
    return this.trackingService.completeRemediation(
      id,
      body.actor,
      body.effectiveness,
      body.effectivenessReason
    );
  }

  @Post(':id/verify')
  async verifyRemediation(
    @Param('id') id: string,
    @Body() body: {
      verifiedBy: string;
      verificationTestId: string;
      effective: boolean;
    }
  ): Promise<RemediationTracking> {
    return this.trackingService.verifyRemediation(
      id,
      body.verifiedBy,
      body.verificationTestId,
      body.effective
    );
  }

  @Post('violation/:violationId/recurrence')
  async trackRecurrence(@Param('violationId') violationId: string): Promise<void> {
    return this.trackingService.trackRecurrence(violationId);
  }

  @Get('metrics/summary')
  async getMetrics(@Query('violationId') violationId?: string): Promise<RemediationMetrics[]> {
    return this.trackingService.getMetrics(violationId);
  }

  @Post(':id/milestones')
  async addMilestone(
    @Param('id') id: string,
    @Body() milestone: any
  ): Promise<RemediationTracking> {
    return this.trackingService.addMilestone(id, milestone);
  }

  @Patch(':id/milestones/:milestoneId')
  async updateMilestone(
    @Param('id') id: string,
    @Param('milestoneId') milestoneId: string,
    @Body() updates: any
  ): Promise<RemediationTracking> {
    return this.trackingService.updateMilestone(id, milestoneId, updates);
  }

  @Post(':id/steps')
  async addStep(
    @Param('id') id: string,
    @Body() step: any
  ): Promise<RemediationTracking> {
    return this.trackingService.addStep(id, step);
  }

  @Patch(':id/steps/:stepId')
  async updateStep(
    @Param('id') id: string,
    @Param('stepId') stepId: string,
    @Body() updates: any
  ): Promise<RemediationTracking> {
    return this.trackingService.updateStep(id, stepId, updates);
  }

  @Get('automation/metrics')
  async getAutomationMetrics(
    @Query('applicationId') applicationId?: string,
    @Query('teamName') teamName?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ) {
    return this.automationService.getMetrics({
      applicationId,
      teamName,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });
  }

  @Post('automation/check-deadlines')
  @HttpCode(HttpStatus.OK)
  async checkDeadlines() {
    await this.automationService.checkDeadlines();
    return { message: 'Deadline check completed' };
  }
}

