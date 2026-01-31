import { Injectable, NotFoundException } from '@nestjs/common';
import { PolicyTemplate, CreateTemplateDto, UpdateTemplateDto } from '../dto/create-template.dto';
import { PolicyType } from '../dto/create-policy.dto';
import { AppLogger } from '../../common/services/logger.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class PolicyTemplatesService {
  private readonly templatesFile = path.join(process.cwd(), '..', 'data', 'policy-templates.json');
  private templates: PolicyTemplate[] = [];
  private readonly logger = new AppLogger(PolicyTemplatesService.name);

  constructor() {
    this.loadTemplates().catch(err => {
      this.logger.error('Error loading templates on startup', err instanceof Error ? err.stack : String(err));
    });
  }

  private async loadTemplates(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.templatesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.templatesFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.templates = (Array.isArray(parsed) ? parsed : []).map((template: any) => ({
          ...template,
          createdAt: new Date(template.createdAt),
          updatedAt: new Date(template.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.templates = [];
          await this.initializeDefaultTemplates();
          await this.saveTemplates();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading templates:', error);
      this.templates = [];
      await this.initializeDefaultTemplates();
    }
  }

  private async saveTemplates(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.templatesFile), { recursive: true });
      await fs.writeFile(this.templatesFile, JSON.stringify(this.templates, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving templates:', error);
      throw error;
    }
  }

  private async initializeDefaultTemplates(): Promise<void> {
    const defaultTemplates: PolicyTemplate[] = [
      {
        id: uuidv4(),
        name: 'Department-Based Access',
        description: 'RBAC policy template for department-based access control',
        type: PolicyType.RBAC,
        category: 'department',
        tags: ['rbac', 'department', 'access-control'],
        template: {
          name: 'Department Access Policy',
          description: 'Controls access based on user department',
          type: PolicyType.RBAC,
          version: '1.0.0',
          status: 'draft',
          rules: [
            {
              id: 'department-match',
              description: 'Allow access if user department matches resource department',
              effect: 'allow',
              conditions: {
                'subject.department': '{{resource.department}}',
              },
            },
          ],
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        usageCount: 0,
      },
      {
        id: uuidv4(),
        name: 'Role-Based Admin Access',
        description: 'RBAC policy template for admin role access',
        type: PolicyType.RBAC,
        category: 'role',
        tags: ['rbac', 'role', 'admin'],
        template: {
          name: 'Admin Role Policy',
          description: 'Grants full access to admin role',
          type: PolicyType.RBAC,
          version: '1.0.0',
          status: 'draft',
          rules: [
            {
              id: 'admin-full-access',
              description: 'Full access for admin role',
              effect: 'allow',
              conditions: {
                'subject.role': 'admin',
              },
            },
          ],
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        usageCount: 0,
      },
      {
        id: uuidv4(),
        name: 'Clearance Level Access',
        description: 'ABAC policy template for clearance level-based access',
        type: PolicyType.ABAC,
        category: 'compliance',
        tags: ['abac', 'clearance', 'security'],
        template: {
          name: 'Clearance Level Policy',
          description: 'Controls access based on clearance level',
          type: PolicyType.ABAC,
          version: '1.0.0',
          status: 'draft',
          effect: 'allow',
          priority: 200,
          conditions: [
            {
              attribute: 'subject.clearanceLevel',
              operator: 'greaterThan',
              value: '{{resource.minClearanceLevel}}',
            },
          ],
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        usageCount: 0,
      },
      {
        id: uuidv4(),
        name: 'Data Classification Match',
        description: 'ABAC policy template for data classification matching',
        type: PolicyType.ABAC,
        category: 'resource',
        tags: ['abac', 'data-classification', 'compliance'],
        template: {
          name: 'Data Classification Policy',
          description: 'Ensures user clearance matches resource classification',
          type: PolicyType.ABAC,
          version: '1.0.0',
          status: 'draft',
          effect: 'allow',
          priority: 150,
          conditions: [
            {
              attribute: 'subject.dataClassification',
              operator: 'equals',
              value: '{{resource.dataClassification}}',
            },
          ],
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        usageCount: 0,
      },
      {
        id: uuidv4(),
        name: 'Multi-Condition Access',
        description: 'ABAC policy template with multiple conditions',
        type: PolicyType.ABAC,
        category: 'custom',
        tags: ['abac', 'multi-condition', 'complex'],
        template: {
          name: 'Multi-Condition Policy',
          description: 'Policy with multiple attribute conditions',
          type: PolicyType.ABAC,
          version: '1.0.0',
          status: 'draft',
          effect: 'allow',
          priority: 100,
          conditions: [
            {
              attribute: 'subject.department',
              operator: 'equals',
              value: '{{resource.department}}',
            },
            {
              attribute: 'subject.clearanceLevel',
              operator: 'greaterThan',
              value: '{{resource.minClearanceLevel}}',
              logicalOperator: 'AND',
            },
          ],
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        usageCount: 0,
      },
    ];

    this.templates = defaultTemplates;
  }

  async findAll(category?: string, type?: PolicyType, tags?: string[]): Promise<PolicyTemplate[]> {
    await this.loadTemplates();
    let filtered = [...this.templates];

    if (category) {
      filtered = filtered.filter(t => t.category === category);
    }
    if (type) {
      filtered = filtered.filter(t => t.type === type);
    }
    if (tags && tags.length > 0) {
      filtered = filtered.filter(t => tags.some(tag => t.tags.includes(tag)));
    }

    return filtered;
  }

  async findOne(id: string): Promise<PolicyTemplate> {
    await this.loadTemplates();
    const template = this.templates.find(t => t.id === id);
    if (!template) {
      throw new NotFoundException(`Template with ID "${id}" not found`);
    }
    return template;
  }

  async create(createTemplateDto: CreateTemplateDto): Promise<PolicyTemplate> {
    await this.loadTemplates();
    const template: PolicyTemplate = {
      id: uuidv4(),
      name: createTemplateDto.name,
      description: createTemplateDto.description,
      type: createTemplateDto.type,
      category: createTemplateDto.category,
      tags: createTemplateDto.tags || [],
      template: createTemplateDto.template,
      createdAt: new Date(),
      updatedAt: new Date(),
      usageCount: 0,
    };

    this.templates.push(template);
    await this.saveTemplates();
    return template;
  }

  async update(id: string, updateTemplateDto: UpdateTemplateDto): Promise<PolicyTemplate> {
    await this.loadTemplates();
    const index = this.templates.findIndex(t => t.id === id);
    if (index === -1) {
      throw new NotFoundException(`Template with ID "${id}" not found`);
    }

    this.templates[index] = {
      ...this.templates[index],
      ...updateTemplateDto,
      updatedAt: new Date(),
    };

    await this.saveTemplates();
    return this.templates[index];
  }

  async remove(id: string): Promise<void> {
    await this.loadTemplates();
    const index = this.templates.findIndex(t => t.id === id);
    if (index === -1) {
      throw new NotFoundException(`Template with ID "${id}" not found`);
    }

    this.templates.splice(index, 1);
    await this.saveTemplates();
  }

  async incrementUsage(id: string): Promise<void> {
    await this.loadTemplates();
    const template = this.templates.find(t => t.id === id);
    if (template) {
      template.usageCount = (template.usageCount || 0) + 1;
      await this.saveTemplates();
    }
  }
}
