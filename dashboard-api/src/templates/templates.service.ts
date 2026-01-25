import { Injectable, NotFoundException } from '@nestjs/common';
import * as path from 'path';
import {
  listTemplates,
  getTemplate,
  getTemplateDescription,
  TemplateName,
} from '../../../heimdall-framework/cli/templates';
import {
  RBACTemplateConfig,
  createRBACTemplate,
} from '../../../heimdall-framework/cli/templates/rbac-template';
import {
  ABACTemplateConfig,
  createABACTemplate,
} from '../../../heimdall-framework/cli/templates/abac-template';
import {
  HIPAATemplateConfig,
  createHIPAATemplate,
} from '../../../heimdall-framework/cli/templates/hipaa-template';
import {
  GDPRTemplateConfig,
  createGDPRTemplate,
} from '../../../heimdall-framework/cli/templates/gdpr-template';
import { CreateFromTemplateDto } from './dto/create-from-template.dto';
import { ABACPolicy } from '../../../heimdall-framework/core/types';
import { PoliciesService } from '../policies/policies.service';
import { CreatePolicyDto, PolicyType } from '../policies/dto/create-policy.dto';

@Injectable()
export class TemplatesService {
  constructor(private readonly policiesService: PoliciesService) {}

  async listTemplates() {
    const templateNames = listTemplates();
    return templateNames.map(name => {
      const template = getTemplate(name as TemplateName);
      return {
        name,
        displayName: template?.name || name.toUpperCase(),
        description: template?.description || '',
      };
    });
  }

  async getTemplate(name: string) {
    const template = getTemplate(name as TemplateName);
    if (!template) {
      throw new NotFoundException(`Template "${name}" not found`);
    }

    const description = getTemplateDescription(name as TemplateName);
    return {
      name,
      displayName: template.name,
      description: template.description,
      fullDescription: description,
      configSchema: this.getConfigSchema(name as TemplateName),
    };
  }

  async createFromTemplate(dto: CreateFromTemplateDto) {
    const template = getTemplate(dto.templateName as TemplateName);
    if (!template) {
      throw new NotFoundException(`Template "${dto.templateName}" not found`);
    }

    // Convert DTO config to template-specific config
    const config = this.convertConfig(dto.templateName as TemplateName, dto);
    const policies = template.create(config);

    // Convert ABAC policies to Policy entities and save them
    const createdPolicies = [];
    for (const abacPolicy of policies) {
      const policyDto: CreatePolicyDto = {
        name: abacPolicy.name,
        description: abacPolicy.description,
        type: PolicyType.ABAC,
        version: '1.0.0',
        effect: abacPolicy.effect === 'allow' ? PolicyEffect.ALLOW : PolicyEffect.DENY,
        priority: abacPolicy.priority || 100,
        conditions: abacPolicy.conditions.map(cond => ({
          attribute: cond.attribute,
          operator: cond.operator,
          value: cond.value,
          logicalOperator: cond.logicalOperator,
        })),
        applicationId: dto.config?.applicationId as string | undefined,
      };

      const policy = await this.policiesService.create(policyDto);
      createdPolicies.push(policy);
    }

    return {
      templateName: dto.templateName,
      policiesCreated: createdPolicies.length,
      policies: createdPolicies,
    };
  }

  private convertConfig(
    templateName: TemplateName,
    dto: CreateFromTemplateDto,
  ): RBACTemplateConfig | ABACTemplateConfig | HIPAATemplateConfig | GDPRTemplateConfig {
    const baseConfig = { applicationName: dto.applicationName };

    switch (templateName) {
      case 'rbac':
        return {
          ...baseConfig,
          roles: dto.config.roles || ['admin', 'user', 'viewer'],
          resources: dto.config.resources || ['dataset', 'report'],
          actions: dto.config.actions || ['read', 'write'],
        } as RBACTemplateConfig;

      case 'abac':
        return {
          ...baseConfig,
          departments: dto.config.departments,
          clearanceLevels: dto.config.clearanceLevels,
          dataClassifications: dto.config.dataClassifications,
          projects: dto.config.projects,
        } as ABACTemplateConfig;

      case 'hipaa':
        return {
          ...baseConfig,
          coveredEntities: dto.config.coveredEntities,
          businessAssociates: dto.config.businessAssociates,
        } as HIPAATemplateConfig;

      case 'gdpr':
        return {
          ...baseConfig,
          dataControllers: dto.config.dataControllers,
          dataProcessors: dto.config.dataProcessors,
          euMemberStates: dto.config.euMemberStates,
        } as GDPRTemplateConfig;

      default:
        return baseConfig as any;
    }
  }

  private getConfigSchema(templateName: TemplateName): any {
    switch (templateName) {
      case 'rbac':
        return {
          type: 'object',
          properties: {
            roles: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of role names',
              example: ['admin', 'user', 'viewer'],
            },
            resources: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of resource types',
              example: ['dataset', 'report'],
            },
            actions: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of actions',
              example: ['read', 'write'],
            },
          },
        };

      case 'abac':
        return {
          type: 'object',
          properties: {
            departments: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of department names',
            },
            clearanceLevels: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of clearance levels',
            },
            dataClassifications: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of data classifications',
            },
            projects: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of project names',
            },
          },
        };

      case 'hipaa':
        return {
          type: 'object',
          properties: {
            coveredEntities: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of covered entity names',
            },
            businessAssociates: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of business associate names',
            },
          },
        };

      case 'gdpr':
        return {
          type: 'object',
          properties: {
            dataControllers: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of data controller names',
            },
            dataProcessors: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of data processor names',
            },
            euMemberStates: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of EU member state codes',
            },
          },
        };

      default:
        return {};
    }
  }
}
