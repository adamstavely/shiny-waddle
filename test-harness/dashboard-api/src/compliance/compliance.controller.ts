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

@Controller('api/compliance')
export class ComplianceController {
  constructor(private readonly complianceService: ComplianceService) {}

  // Framework Management
  @Get('frameworks')
  getAvailableFrameworks(): ComplianceFramework[] {
    return this.complianceService.getAvailableFrameworks();
  }

  @Get('frameworks/:framework')
  getFrameworkMetadata(@Param('framework') framework: ComplianceFramework) {
    return this.complianceService.getFrameworkMetadata(framework);
  }

  @Get('frameworks/:framework/controls')
  getControls(@Param('framework') framework: ComplianceFramework): ComplianceControl[] {
    return this.complianceService.getControls(framework);
  }

  @Get('frameworks/:framework/controls/:controlId')
  getControl(
    @Param('framework') framework: ComplianceFramework,
    @Param('controlId') controlId: string
  ): ComplianceControl | null {
    return this.complianceService.getControl(framework, controlId);
  }

  // Mapping Management
  @Post('mappings')
  @HttpCode(HttpStatus.CREATED)
  async createMapping(
    @Body(ValidationPipe) dto: CreateComplianceMappingDto
  ): Promise<ComplianceMapping> {
    return this.complianceService.createMapping(dto);
  }

  @Get('mappings')
  async findAllMappings(@Query('framework') framework?: ComplianceFramework): Promise<ComplianceMapping[]> {
    return this.complianceService.findAllMappings(framework);
  }

  @Get('mappings/:id')
  async findOneMapping(@Param('id') id: string): Promise<ComplianceMapping> {
    return this.complianceService.findOneMapping(id);
  }

  @Patch('mappings/:id')
  async updateMapping(
    @Param('id') id: string,
    @Body() updates: Partial<ComplianceMapping>
  ): Promise<ComplianceMapping> {
    return this.complianceService.updateMapping(id, updates);
  }

  @Post('mappings/:id/evidence')
  async addEvidence(
    @Param('id') id: string,
    @Body() evidence: any
  ): Promise<ComplianceMapping> {
    return this.complianceService.addEvidence(id, evidence);
  }

  // Assessment Management
  @Post('assessments')
  @HttpCode(HttpStatus.CREATED)
  async createAssessment(
    @Body(ValidationPipe) dto: CreateComplianceAssessmentDto
  ): Promise<ComplianceAssessment> {
    return this.complianceService.createAssessment(dto);
  }

  @Get('assessments')
  async findAllAssessments(@Query('framework') framework?: ComplianceFramework): Promise<ComplianceAssessment[]> {
    return this.complianceService.findAllAssessments(framework);
  }

  @Get('assessments/:id')
  async findOneAssessment(@Param('id') id: string): Promise<ComplianceAssessment> {
    return this.complianceService.findOneAssessment(id);
  }

  @Get('frameworks/:framework/current-assessment')
  async getCurrentAssessment(@Param('framework') framework: ComplianceFramework): Promise<ComplianceAssessment | null> {
    return this.complianceService.getCurrentAssessment(framework);
  }

  // Gap Analysis
  @Get('frameworks/:framework/gaps')
  async performGapAnalysis(@Param('framework') framework: ComplianceFramework): Promise<ComplianceGap[]> {
    return this.complianceService.performGapAnalysis(framework);
  }

  // Roadmap Management
  @Post('frameworks/:framework/roadmaps')
  @HttpCode(HttpStatus.CREATED)
  async createRoadmap(
    @Param('framework') framework: ComplianceFramework,
    @Body() body: { name: string; description?: string; targetDate?: Date }
  ): Promise<ComplianceRoadmap> {
    return this.complianceService.createRoadmap(framework, body.name, body.description, body.targetDate);
  }

  @Get('roadmaps')
  async findAllRoadmaps(@Query('framework') framework?: ComplianceFramework): Promise<ComplianceRoadmap[]> {
    return this.complianceService.findAllRoadmaps(framework);
  }

  @Get('roadmaps/:id')
  async findOneRoadmap(@Param('id') id: string): Promise<ComplianceRoadmap> {
    return this.complianceService.findOneRoadmap(id);
  }

  @Patch('roadmaps/:id')
  async updateRoadmap(
    @Param('id') id: string,
    @Body() updates: Partial<ComplianceRoadmap>
  ): Promise<ComplianceRoadmap> {
    return this.complianceService.updateRoadmap(id, updates);
  }
}

