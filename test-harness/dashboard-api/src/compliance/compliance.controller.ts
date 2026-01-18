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
import { ComplianceService } from './compliance.service';
import {
  ComplianceControl,
  ComplianceMapping,
  ComplianceAssessment,
  ComplianceGap,
  ComplianceRoadmap,
  ComplianceFramework,
  CreateComplianceMappingDto,
  CreateComplianceAssessmentDto,
} from './entities/compliance.entity';
import { Public } from '../auth/decorators/public.decorator';

@Controller('api/v1/compliance')
export class ComplianceController {
  constructor(private readonly complianceService: ComplianceService) {}

  // Framework Management
  @Public()
  @Get('frameworks')
  getAvailableFrameworks(): ComplianceFramework[] {
    return this.complianceService.getAvailableFrameworks();
  }

  @Public()
  @Get('frameworks/:framework')
  getFrameworkMetadata(@Param('framework') framework: ComplianceFramework) {
    return this.complianceService.getFrameworkMetadata(framework);
  }

  @Public()
  @Get('frameworks/:framework/controls')
  getControls(@Param('framework') framework: ComplianceFramework): ComplianceControl[] {
    return this.complianceService.getControls(framework);
  }

  @Public()
  @Get('frameworks/:framework/controls/:controlId')
  getControl(
    @Param('framework') framework: ComplianceFramework,
    @Param('controlId') controlId: string
  ): ComplianceControl | null {
    return this.complianceService.getControl(framework, controlId);
  }

  // Mapping Management
  @Public()
  @Post('mappings')
  @HttpCode(HttpStatus.CREATED)
  async createMapping(
    @Body(ValidationPipe) dto: CreateComplianceMappingDto
  ): Promise<ComplianceMapping> {
    return this.complianceService.createMapping(dto);
  }

  @Public()
  @Get('mappings')
  async findAllMappings(@Query('framework') framework?: ComplianceFramework): Promise<ComplianceMapping[]> {
    return this.complianceService.findAllMappings(framework);
  }

  @Public()
  @Get('mappings/:id')
  async findOneMapping(@Param('id') id: string): Promise<ComplianceMapping> {
    return this.complianceService.findOneMapping(id);
  }

  @Public()
  @Patch('mappings/:id')
  async updateMapping(
    @Param('id') id: string,
    @Body() updates: Partial<ComplianceMapping>
  ): Promise<ComplianceMapping> {
    return this.complianceService.updateMapping(id, updates);
  }

  @Public()
  @Post('mappings/:id/evidence')
  async addEvidence(
    @Param('id') id: string,
    @Body() evidence: any
  ): Promise<ComplianceMapping> {
    return this.complianceService.addEvidence(id, evidence);
  }

  // Assessment Management
  @Public()
  @Post('assessments')
  @HttpCode(HttpStatus.CREATED)
  async createAssessment(
    @Body(ValidationPipe) dto: CreateComplianceAssessmentDto
  ): Promise<ComplianceAssessment> {
    return this.complianceService.createAssessment(dto);
  }

  @Public()
  @Get('assessments')
  async findAllAssessments(@Query('framework') framework?: ComplianceFramework): Promise<ComplianceAssessment[]> {
    return this.complianceService.findAllAssessments(framework);
  }

  @Public()
  @Get('assessments/:id')
  async findOneAssessment(@Param('id') id: string): Promise<ComplianceAssessment> {
    return this.complianceService.findOneAssessment(id);
  }

  @Public()
  @Get('frameworks/:framework/current-assessment')
  async getCurrentAssessment(@Param('framework') framework: ComplianceFramework): Promise<ComplianceAssessment | null> {
    return this.complianceService.getCurrentAssessment(framework);
  }

  // Gap Analysis
  @Public()
  @Get('frameworks/:framework/gaps')
  async performGapAnalysis(@Param('framework') framework: ComplianceFramework): Promise<ComplianceGap[]> {
    return this.complianceService.performGapAnalysis(framework);
  }

  // Roadmap Management
  @Public()
  @Post('frameworks/:framework/roadmaps')
  @HttpCode(HttpStatus.CREATED)
  async createRoadmap(
    @Param('framework') framework: ComplianceFramework,
    @Body() body: { name: string; description?: string; targetDate?: Date }
  ): Promise<ComplianceRoadmap> {
    return this.complianceService.createRoadmap(framework, body.name, body.description, body.targetDate);
  }

  @Public()
  @Get('roadmaps')
  async findAllRoadmaps(@Query('framework') framework?: ComplianceFramework): Promise<ComplianceRoadmap[]> {
    return this.complianceService.findAllRoadmaps(framework);
  }

  @Public()
  @Get('roadmaps/:id')
  async findOneRoadmap(@Param('id') id: string): Promise<ComplianceRoadmap> {
    return this.complianceService.findOneRoadmap(id);
  }

  @Public()
  @Patch('roadmaps/:id')
  async updateRoadmap(
    @Param('id') id: string,
    @Body() updates: Partial<ComplianceRoadmap>
  ): Promise<ComplianceRoadmap> {
    return this.complianceService.updateRoadmap(id, updates);
  }
}

