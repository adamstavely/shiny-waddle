import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  Query,
  ValidationPipe,
  HttpException,
} from '@nestjs/common';
import { PoliciesService } from './policies.service';
import { CreatePolicyDto, PolicyType, PolicyStatus } from './dto/create-policy.dto';
import { UpdatePolicyDto } from './dto/update-policy.dto';
import { Policy, PolicyVersion } from './entities/policy.entity';
import { PolicyTemplatesService } from './services/policy-templates.service';
import { CreateTemplateDto, UpdateTemplateDto, PolicyTemplate } from './dto/create-template.dto';
import { PolicyDiffService, EnhancedVersionComparison } from './services/policy-diff.service';
import { SystemStateComparisonService, ComplianceAnalysis, SystemStateComparison } from './services/system-state-comparison.service';
import { DataTagComparisonService, TagComparison, TagUpdateGuidance } from './services/data-tag-comparison.service';
import { GapAnalysisService, GapAnalysis, RemediationGuidance } from './services/gap-analysis.service';
import { AISummaryService, ExecutiveSummary, DetailedSummary } from './services/ai-summary.service';
import { LLMIntegrationService, PolicyRecommendation, QueryResponse } from './services/llm-integration.service';
import { CacheService } from './services/cache.service';
import { PolicyNotFoundException, SummaryGenerationException } from './exceptions/policy-exceptions';
import { ReportSchedulerService, ScheduledReport } from './services/report-scheduler.service';
import { AutomationService, AutomationRule, RemediationResult } from './services/automation.service';
import { PolicyNotificationsService, PolicyChangeNotification, NotificationPreferences } from './services/policy-notifications.service';
import { CollaborationService, PolicyComment, PolicyApproval } from './services/collaboration.service';

@Controller('api/policies')
export class PoliciesController {
  constructor(
    private readonly policiesService: PoliciesService,
    private readonly templatesService: PolicyTemplatesService,
    private readonly diffService: PolicyDiffService,
    private readonly systemStateService: SystemStateComparisonService,
    private readonly tagComparisonService: DataTagComparisonService,
    private readonly gapAnalysisService: GapAnalysisService,
    private readonly aiSummaryService: AISummaryService,
    private readonly llmService: LLMIntegrationService,
    private readonly cacheService: CacheService,
    private readonly reportSchedulerService: ReportSchedulerService,
    private readonly automationService: AutomationService,
    private readonly notificationsService: PolicyNotificationsService,
    private readonly collaborationService: CollaborationService,
  ) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body(ValidationPipe) createPolicyDto: CreatePolicyDto): Promise<Policy> {
    const policy = await this.policiesService.create(createPolicyDto);
    
    // Trigger automation and notifications (non-blocking)
    Promise.all([
      this.automationService.processPolicyChange(policy.id, 'created').catch(err => 
        console.error('Error processing automation for policy creation:', err)
      ),
      this.notificationsService.notifyPolicyChange(
        policy.id,
        'created',
        (createPolicyDto as any).createdBy || 'system',
      ).catch(err => 
        console.error('Error sending policy creation notification:', err)
      ),
    ]);
    
    return policy;
  }

  @Get()
  async findAll(
    @Query('type') type?: PolicyType,
    @Query('status') status?: PolicyStatus,
    @Query('applicationId') applicationId?: string,
  ): Promise<Policy[]> {
    return this.policiesService.findAll(type, status, applicationId);
  }

  // Specific routes must be defined before parameterized routes
  @Get('enforcement-gaps')
  async getEnforcementGaps(
    @Query('applicationId') applicationId?: string,
    @Query('policyId') policyId?: string,
  ): Promise<any[]> {
    const policyIds = policyId ? [policyId] : undefined;
    return this.systemStateService.detectEnforcementGaps(policyIds);
  }

  @Get('compliance-analysis')
  async getComplianceAnalysis(
    @Query('applicationId') applicationId?: string,
  ): Promise<ComplianceAnalysis> {
    try {
      return await this.systemStateService.analyzeCompliance(applicationId);
    } catch (error: any) {
      console.error('Error in getComplianceAnalysis:', error);
      throw new Error(`Failed to analyze compliance: ${error.message}`);
    }
  }

  @Get('gap-analysis')
  async getGapAnalysis(
    @Query('policyId') policyId?: string,
    @Query('applicationId') applicationId?: string,
  ): Promise<GapAnalysis> {
    try {
      return await this.gapAnalysisService.analyzeGaps(policyId, applicationId);
    } catch (error: any) {
      console.error('Error in getGapAnalysis:', error);
      throw new Error(`Failed to analyze gaps: ${error.message}`);
    }
  }

  @Get('templates')
  async getTemplates(
    @Query('category') category?: string,
    @Query('type') type?: PolicyType,
    @Query('tags') tags?: string,
  ): Promise<PolicyTemplate[]> {
    const tagArray = tags ? tags.split(',') : undefined;
    return this.templatesService.findAll(category, type, tagArray);
  }

  @Get('tags/compare-all')
  async compareAllTags(
    @Query('policyId') policyId?: string,
  ): Promise<TagComparison[]> {
    return this.tagComparisonService.compareAllTags(policyId);
  }

  @Get('summaries/executive')
  async getExecutiveSummary(
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
  ): Promise<ExecutiveSummary> {
    try {
      const start = new Date(startDate);
      const end = new Date(endDate);

      // Validate date range
      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        throw new HttpException(
          {
            statusCode: HttpStatus.BAD_REQUEST,
            message: 'Invalid date format. Use ISO 8601 format (YYYY-MM-DD)',
            error: 'Invalid Date',
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      if (start > end) {
        throw new HttpException(
          {
            statusCode: HttpStatus.BAD_REQUEST,
            message: 'Start date must be before end date',
            error: 'Invalid Date Range',
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      return await this.aiSummaryService.generateExecutiveSummary(start, end);
    } catch (error: any) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new SummaryGenerationException(
        error.message || 'Failed to generate executive summary',
        error,
      );
    }
  }

  @Get('summaries/detailed')
  async getDetailedSummary(
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
  ): Promise<DetailedSummary> {
    try {
      const start = new Date(startDate);
      const end = new Date(endDate);

      // Validate date range
      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        throw new HttpException(
          {
            statusCode: HttpStatus.BAD_REQUEST,
            message: 'Invalid date format. Use ISO 8601 format (YYYY-MM-DD)',
            error: 'Invalid Date',
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      if (start > end) {
        throw new HttpException(
          {
            statusCode: HttpStatus.BAD_REQUEST,
            message: 'Start date must be before end date',
            error: 'Invalid Date Range',
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      return await this.aiSummaryService.generateDetailedSummary(start, end);
    } catch (error: any) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new SummaryGenerationException(
        error.message || 'Failed to generate detailed summary',
        error,
      );
    }
  }

  @Get('summaries/compliance')
  async getComplianceSummary(): Promise<{ summary: string }> {
    const summary = await this.aiSummaryService.generateComplianceSummary();
    return { summary };
  }

  @Get(':id/recommendations')
  async getPolicyRecommendations(@Param('id') id: string): Promise<PolicyRecommendation[]> {
    try {
      // Check cache first
      const cached = await this.cacheService.getCachedRecommendations(id);
      if (cached) {
        return cached;
      }

      const policy = await this.policiesService.findOne(id);
      if (!policy) {
        throw new PolicyNotFoundException(id);
      }

    // Get compliance issues for context
    const complianceAnalysis = await this.systemStateService.analyzeCompliance();
    const gaps = await this.gapAnalysisService.analyzeGaps(id);

    const recommendations = await this.llmService.generatePolicyRecommendations(policy, {
      complianceIssues: gaps.gaps || [],
    });

      // Cache recommendations for 30 minutes
      await this.cacheService.cacheRecommendations(id, recommendations, 1800);

      return recommendations;
    } catch (error: any) {
      if (error instanceof PolicyNotFoundException) {
        throw error;
      }
      // Log error and return empty array as fallback
      console.error('Error generating recommendations:', error);
      return [];
    }
  }

  @Post('query')
  @HttpCode(HttpStatus.OK)
  async answerQuery(
    @Body() body: { query: string; policyIds?: string[] },
  ): Promise<QueryResponse> {
    try {
      if (!body.query || body.query.trim().length === 0) {
        throw new HttpException(
          {
            statusCode: HttpStatus.BAD_REQUEST,
            message: 'Query is required and cannot be empty',
            error: 'Invalid Query',
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      const policies = body.policyIds
        ? await Promise.all(body.policyIds.map(id => this.policiesService.findOne(id)))
        : await this.policiesService.findAll();

      const complianceAnalysis = await this.systemStateService.analyzeCompliance();

      return await this.llmService.answerQuery(body.query, {
        policies: policies.filter(Boolean) as Policy[],
        compliance: complianceAnalysis,
      });
    } catch (error: any) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        {
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: `Failed to process query: ${error.message || 'Unknown error'}`,
          error: 'Query Processing Failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('domain-configs')
  async getAllDomainConfigs(): Promise<Record<string, any>> {
    return this.policiesService.getAllDomainConfigs();
  }

  @Post('compare')
  async comparePolicies(
    @Body() body: { policyId1: string; policyId2: string },
  ): Promise<any> {
    const policy1 = await this.policiesService.findOne(body.policyId1);
    const policy2 = await this.policiesService.findOne(body.policyId2);
    return this.diffService.comparePolicies(policy1, policy2);
  }

  @Get('templates/:id')
  async getTemplate(@Param('id') id: string): Promise<PolicyTemplate> {
    return this.templatesService.findOne(id);
  }

  @Get('tags/compare/:resourceId')
  async compareTags(
    @Param('resourceId') resourceId: string,
    @Query('policyId') policyId?: string,
  ): Promise<TagComparison> {
    return this.tagComparisonService.compareTags(resourceId, policyId);
  }

  @Get('tags/guidance/:resourceId')
  async getTagGuidance(
    @Param('resourceId') resourceId: string,
    @Query('policyId') policyId?: string,
  ): Promise<TagUpdateGuidance> {
    const comparison = await this.tagComparisonService.compareTags(resourceId, policyId);
    return this.tagComparisonService.generateTagGuidance(comparison);
  }

  @Get('gaps/:gapId/remediation')
  async getRemediationGuidance(@Param('gapId') gapId: string): Promise<RemediationGuidance | null> {
    return this.gapAnalysisService.getRemediationGuidance(gapId);
  }

  @Post('gaps/:gapId/progress')
  @HttpCode(HttpStatus.OK)
  async trackGapProgress(
    @Param('gapId') gapId: string,
    @Body() body: { step: number; completed: boolean; notes?: string },
  ): Promise<{ success: boolean }> {
    await this.gapAnalysisService.trackProgress(gapId, body.step, body.completed, body.notes);
    return { success: true };
  }

  @Get('domain-configs/:domain')
  async getDomainConfig(@Param('domain') domain: string): Promise<any> {
    return this.policiesService.getDomainConfig(domain);
  }

  @Post('domain-configs/:domain')
  @HttpCode(HttpStatus.OK)
  async saveDomainConfig(
    @Param('domain') domain: string,
    @Body() config: any,
  ): Promise<any> {
    await this.policiesService.saveDomainConfig(domain, config);
    return { message: 'Domain configuration saved successfully' };
  }

  @Post('templates')
  @HttpCode(HttpStatus.CREATED)
  async createTemplate(
    @Body(ValidationPipe) createTemplateDto: CreateTemplateDto,
  ): Promise<PolicyTemplate> {
    return this.templatesService.create(createTemplateDto);
  }

  @Patch('templates/:id')
  async updateTemplate(
    @Param('id') id: string,
    @Body(ValidationPipe) updateTemplateDto: UpdateTemplateDto,
  ): Promise<PolicyTemplate> {
    return this.templatesService.update(id, updateTemplateDto);
  }

  @Delete('templates/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteTemplate(@Param('id') id: string): Promise<void> {
    return this.templatesService.remove(id);
  }

  @Post('templates/:id/use')
  @HttpCode(HttpStatus.OK)
  async useTemplate(@Param('id') id: string): Promise<PolicyTemplate> {
    await this.templatesService.incrementUsage(id);
    return this.templatesService.findOne(id);
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<Policy> {
    return this.policiesService.findOne(id);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) updatePolicyDto: UpdatePolicyDto,
  ): Promise<Policy> {
    const policy = await this.policiesService.update(id, updatePolicyDto);
    
    // Trigger automation, notifications, and cache invalidation (non-blocking)
    Promise.all([
      this.automationService.processPolicyChange(id, 'modified').catch(err => 
        console.error('Error processing automation for policy update:', err)
      ),
      this.notificationsService.notifyPolicyChange(
        id,
        'modified',
        (updatePolicyDto as any).updatedBy || 'system',
      ).catch(err => 
        console.error('Error sending policy update notification:', err)
      ),
      this.cacheService.invalidatePolicyCache(id).catch(err => 
        console.error('Error invalidating cache:', err)
      ),
    ]);
    
    return policy;
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string): Promise<void> {
    return this.policiesService.remove(id);
  }

  @Get(':id/versions')
  async getVersions(@Param('id') id: string): Promise<PolicyVersion[]> {
    return this.policiesService.getVersions(id);
  }

  @Post(':id/versions')
  async addVersion(
    @Param('id') id: string,
    @Body(ValidationPipe) version: PolicyVersion,
  ): Promise<Policy> {
    return this.policiesService.addVersion(id, version);
  }

  @Get(':id/compare/:version1/:version2')
  async compareVersions(
    @Param('id') id: string,
    @Param('version1') version1: string,
    @Param('version2') version2: string,
  ): Promise<EnhancedVersionComparison> {
    const policy = await this.policiesService.findOne(id);
    return this.diffService.compareVersions(policy, version1, version2);
  }

  @Post(':id/deploy')
  @HttpCode(HttpStatus.OK)
  async deploy(
    @Param('id') id: string,
    @Body('version') version?: string,
  ): Promise<Policy> {
    return this.policiesService.deploy(id, version);
  }

  @Post(':id/rollback')
  @HttpCode(HttpStatus.OK)
  async rollback(
    @Param('id') id: string,
    @Body('version') version: string,
  ): Promise<Policy> {
    return this.policiesService.rollback(id, version);
  }

  @Get(':id/audit')
  async getAuditLogs(@Param('id') id: string): Promise<any[]> {
    return this.policiesService.getAuditLogs(id);
  }

  @Get(':id/impact-analysis')
  async analyzeImpact(
    @Param('id') id: string,
    @Query('version') version?: string,
  ): Promise<any> {
    return this.policiesService.analyzeImpact(id, version);
  }

  @Post(':id/test')
  @HttpCode(HttpStatus.OK)
  async testPolicy(
    @Param('id') id: string,
    @Body() testData: any,
  ): Promise<any> {
    return this.policiesService.testPolicy(id, testData);
  }

  @Get(':id/tests')
  async getTestsUsingPolicy(@Param('id') id: string): Promise<any[]> {
    return this.policiesService.findTestsUsingPolicy(id);
  }

  @Get(':id/system-state-comparison')
  async getSystemStateComparison(@Param('id') id: string): Promise<SystemStateComparison> {
    return this.systemStateService.compareExpectedVsActual(id);
  }

  @Get('compliance/trends')
  async getComplianceTrends(
    @Query('timeRange') timeRange: string = '30d',
  ): Promise<Array<{ date: string; complianceScore: number; totalGaps: number; criticalGaps: number }>> {
    try {
      // Calculate date range
      const endDate = new Date();
      const startDate = new Date();
      
      switch (timeRange) {
        case '7d':
          startDate.setDate(startDate.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(startDate.getDate() - 30);
          break;
        case '90d':
          startDate.setDate(startDate.getDate() - 90);
          break;
        case '1y':
          startDate.setFullYear(startDate.getFullYear() - 1);
          break;
        default:
          startDate.setDate(startDate.getDate() - 30);
      }

      // Generate mock trend data (in production, this would query historical data)
      const trends = [];
      const daysDiff = Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));
      
      for (let i = 0; i <= daysDiff; i += Math.max(1, Math.floor(daysDiff / 20))) {
        const date = new Date(startDate);
        date.setDate(date.getDate() + i);
        
        // Mock data - in production, query actual historical compliance data
        trends.push({
          date: date.toISOString().split('T')[0],
          complianceScore: 75 + Math.random() * 20, // 75-95%
          totalGaps: Math.floor(Math.random() * 50),
          criticalGaps: Math.floor(Math.random() * 10),
        });
      }

      return trends;
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: `Failed to load compliance trends: ${error.message}`,
          error: 'Trends Loading Failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('reports/scheduled')
  async getScheduledReports(): Promise<ScheduledReport[]> {
    return this.reportSchedulerService.getAllReports();
  }

  @Post('reports/scheduled')
  @HttpCode(HttpStatus.CREATED)
  async createScheduledReport(
    @Body() report: Omit<ScheduledReport, 'id' | 'nextRun'>,
  ): Promise<ScheduledReport> {
    try {
      return await this.reportSchedulerService.createScheduledReport(report);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to create scheduled report: ${error.message}`,
          error: 'Report Creation Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Patch('reports/scheduled/:id')
  async updateScheduledReport(
    @Param('id') id: string,
    @Body() updates: Partial<ScheduledReport>,
  ): Promise<ScheduledReport> {
    try {
      return await this.reportSchedulerService.updateReport(id, updates);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.NOT_FOUND,
          message: error.message || 'Report not found',
          error: 'Report Update Failed',
        },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  @Delete('reports/scheduled/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteScheduledReport(@Param('id') id: string): Promise<void> {
    try {
      await this.reportSchedulerService.deleteReport(id);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.NOT_FOUND,
          message: error.message || 'Report not found',
          error: 'Report Deletion Failed',
        },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  @Post('reports/scheduled/:id/run')
  @HttpCode(HttpStatus.OK)
  async runScheduledReport(@Param('id') id: string): Promise<{ message: string }> {
    try {
      await this.reportSchedulerService.generateAndSendReport(id);
      return { message: 'Report generated and sent successfully' };
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: `Failed to run report: ${error.message}`,
          error: 'Report Generation Failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('automation/rules')
  async getAutomationRules(): Promise<AutomationRule[]> {
    return this.automationService.getAllRules();
  }

  @Post('automation/rules')
  @HttpCode(HttpStatus.CREATED)
  async createAutomationRule(
    @Body() rule: Omit<AutomationRule, 'id' | 'createdAt'>,
  ): Promise<AutomationRule> {
    try {
      return await this.automationService.createRule(rule);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to create automation rule: ${error.message}`,
          error: 'Rule Creation Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Patch('automation/rules/:id')
  async updateAutomationRule(
    @Param('id') id: string,
    @Body() updates: Partial<AutomationRule>,
  ): Promise<AutomationRule> {
    try {
      return await this.automationService.updateRule(id, updates);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.NOT_FOUND,
          message: error.message || 'Rule not found',
          error: 'Rule Update Failed',
        },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  @Delete('automation/rules/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteAutomationRule(@Param('id') id: string): Promise<void> {
    try {
      await this.automationService.deleteRule(id);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.NOT_FOUND,
          message: error.message || 'Rule not found',
          error: 'Rule Deletion Failed',
        },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  @Post('automation/gap-analysis/run')
  @HttpCode(HttpStatus.OK)
  async runScheduledGapAnalysis(
    @Body() body: { policyId?: string },
  ): Promise<GapAnalysis> {
    try {
      return await this.automationService.runScheduledGapAnalysis(body.policyId);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: `Failed to run gap analysis: ${error.message}`,
          error: 'Gap Analysis Failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('automation/process-gap/:gapId')
  @HttpCode(HttpStatus.OK)
  async processGap(
    @Param('gapId') gapId: string,
    @Body() gap: any,
  ): Promise<RemediationResult[]> {
    try {
      return await this.automationService.processGap(gapId, gap);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: `Failed to process gap: ${error.message}`,
          error: 'Gap Processing Failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('notifications/history')
  async getNotificationHistory(
    @Query('policyId') policyId?: string,
  ): Promise<PolicyChangeNotification[]> {
    return this.notificationsService.getNotificationHistory(policyId);
  }

  @Get('notifications/preferences')
  async getNotificationPreferences(
    @Query('userId') userId: string,
  ): Promise<NotificationPreferences | null> {
    return this.notificationsService.getPreferences(userId);
  }

  @Patch('notifications/preferences')
  async updateNotificationPreferences(
    @Query('userId') userId: string,
    @Body() preferences: Partial<NotificationPreferences>,
  ): Promise<NotificationPreferences> {
    return this.notificationsService.setPreferences(userId, preferences);
  }

  @Get(':id/comments')
  async getPolicyComments(@Param('id') id: string): Promise<PolicyComment[]> {
    return this.collaborationService.getComments(id);
  }

  @Post(':id/comments')
  @HttpCode(HttpStatus.CREATED)
  async addComment(
    @Param('id') id: string,
    @Body() body: { userId: string; userName: string; content: string; parentId?: string },
  ): Promise<PolicyComment> {
    try {
      return await this.collaborationService.addComment(
        id,
        body.userId,
        body.userName,
        body.content,
        body.parentId,
      );
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to add comment: ${error.message}`,
          error: 'Comment Creation Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Patch('comments/:commentId')
  async updateComment(
    @Param('commentId') commentId: string,
    @Body() body: { userId: string; content: string },
  ): Promise<PolicyComment> {
    try {
      return await this.collaborationService.updateComment(commentId, body.userId, body.content);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to update comment: ${error.message}`,
          error: 'Comment Update Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Delete('comments/:commentId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteComment(
    @Param('commentId') commentId: string,
    @Query('userId') userId: string,
  ): Promise<void> {
    try {
      await this.collaborationService.deleteComment(commentId, userId);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to delete comment: ${error.message}`,
          error: 'Comment Deletion Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Get(':id/approvals')
  async getPolicyApprovals(@Param('id') id: string): Promise<PolicyApproval[]> {
    return this.collaborationService.getApprovals(id);
  }

  @Post(':id/approvals')
  @HttpCode(HttpStatus.CREATED)
  async createApprovalRequest(
    @Param('id') id: string,
    @Body() body: {
      requestedBy: string;
      stages: Array<{
        approvers: string[];
        requiredApprovals: number;
      }>;
    },
  ): Promise<PolicyApproval> {
    try {
      return await this.collaborationService.createApprovalRequest(
        id,
        body.requestedBy,
        body.stages,
      );
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to create approval request: ${error.message}`,
          error: 'Approval Creation Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Post('approvals/:approvalId/approve')
  @HttpCode(HttpStatus.OK)
  async approvePolicy(
    @Param('approvalId') approvalId: string,
    @Body() body: { approverId: string; comments?: string },
  ): Promise<PolicyApproval> {
    try {
      return await this.collaborationService.approve(approvalId, body.approverId, body.comments);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to approve: ${error.message}`,
          error: 'Approval Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Post('approvals/:approvalId/reject')
  @HttpCode(HttpStatus.OK)
  async rejectPolicy(
    @Param('approvalId') approvalId: string,
    @Body() body: { approverId: string; reason: string },
  ): Promise<PolicyApproval> {
    try {
      return await this.collaborationService.reject(approvalId, body.approverId, body.reason);
    } catch (error: any) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: `Failed to reject: ${error.message}`,
          error: 'Rejection Failed',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}

