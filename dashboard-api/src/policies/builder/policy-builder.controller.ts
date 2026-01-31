import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
} from '@nestjs/common';
import { PolicyBuilderService } from './services/policy-builder.service';
import { PolicyValidationService } from './services/policy-validation.service';
import { PolicyDiffService } from './services/policy-diff.service';
import { PolicyTemplateService } from './services/policy-template.service';
import { CreateBuilderStateDto, UpdateBuilderStateDto, CreatePolicyFromBuilderDto, UpdatePolicyFromBuilderDto } from './dto/create-policy-builder.dto';
import { ValidatePolicyDto } from './dto/validate-policy.dto';
import { TemplateFiltersDto } from './dto/policy-template.dto';
import { PolicyBuilderState } from './entities/policy-builder-state.entity';
import { PolicyTemplate } from './entities/policy-template.entity';
import { Policy } from '../entities/policy.entity';
import { PolicyFormData } from './entities/policy-builder-state.entity';
import { ValidationResult } from './dto/validate-policy.dto';
import { PolicyDiff } from './services/policy-diff.service';

@Controller('api/policies/builder')
export class PolicyBuilderController {
  constructor(
    private readonly builderService: PolicyBuilderService,
    private readonly validationService: PolicyValidationService,
    private readonly diffService: PolicyDiffService,
    private readonly templateService: PolicyTemplateService,
  ) {}

  /**
   * Create a new builder state
   */
  @Post('state')
  @HttpCode(HttpStatus.CREATED)
  async createBuilderState(
    @Body(ValidationPipe) dto: CreateBuilderStateDto
  ): Promise<PolicyBuilderState> {
    return this.builderService.createBuilderState(dto.policyType, dto.policyId);
  }

  /**
   * Get builder state
   */
  @Get('state/:id')
  async getBuilderState(@Param('id') id: string): Promise<PolicyBuilderState> {
    return this.builderService.getBuilderState(id);
  }

  /**
   * Update builder state
   */
  @Patch('state/:id')
  async updateBuilderState(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateBuilderStateDto
  ): Promise<PolicyBuilderState> {
    return this.builderService.updateBuilderState(id, dto);
  }

  /**
   * Convert form data to JSON
   */
  @Post('convert/form-to-json')
  async formToJson(@Body() formData: PolicyFormData): Promise<{ json: string; policy: Policy }> {
    const policy = this.builderService.formDataToPolicy(formData);
    return {
      json: JSON.stringify(policy, null, 2),
      policy,
    };
  }

  /**
   * Convert JSON to form data
   */
  @Post('convert/json-to-form')
  async jsonToForm(@Body() dto: { json: string }): Promise<PolicyFormData> {
    try {
      const policy = JSON.parse(dto.json) as Policy;
      return this.builderService.policyToFormData(policy);
    } catch (error) {
      throw new Error(`Invalid JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate policy
   */
  @Post('validate')
  async validatePolicy(@Body(ValidationPipe) dto: ValidatePolicyDto): Promise<ValidationResult> {
    if (dto.policy) {
      return this.validationService.validatePolicy(dto.policy);
    } else if (dto.json) {
      return this.validationService.validatePolicy(dto.json);
    } else {
      throw new Error('Either policy or json must be provided');
    }
  }

  /**
   * Get all templates
   */
  @Get('templates')
  async getTemplates(@Query() filters: TemplateFiltersDto): Promise<PolicyTemplate[]> {
    return this.templateService.findAll({
      category: filters.category,
      policyType: filters.policyType,
      tags: filters.tags?.split(','),
    });
  }

  /**
   * Get one template
   */
  @Get('templates/:id')
  async getTemplate(@Param('id') id: string): Promise<PolicyTemplate> {
    return this.templateService.findOne(id);
  }

  /**
   * Apply template to builder state
   */
  @Post('state/:stateId/apply-template/:templateId')
  async applyTemplate(
    @Param('stateId') stateId: string,
    @Param('templateId') templateId: string
  ): Promise<PolicyBuilderState> {
    return this.builderService.applyTemplate(stateId, templateId);
  }

  /**
   * Create policy from builder state
   */
  @Post('create-policy')
  @HttpCode(HttpStatus.CREATED)
  async createPolicy(
    @Body(ValidationPipe) dto: CreatePolicyFromBuilderDto
  ): Promise<Policy> {
    return this.builderService.createPolicyFromBuilder(dto.stateId);
  }

  /**
   * Update policy from builder state
   */
  @Post('update-policy/:id')
  async updatePolicy(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdatePolicyFromBuilderDto
  ): Promise<Policy> {
    return this.builderService.updatePolicyFromBuilder(id, dto.stateId);
  }

  /**
   * Compare policy versions
   */
  @Get('diff/:policyId/:version1/:version2')
  async compareVersions(
    @Param('policyId') policyId: string,
    @Param('version1') version1: string,
    @Param('version2') version2: string
  ): Promise<PolicyDiff> {
    return this.diffService.compareVersions(policyId, version1, version2);
  }
}
