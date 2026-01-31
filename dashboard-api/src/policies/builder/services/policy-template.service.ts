import { Injectable, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { PolicyTemplate } from '../entities/policy-template.entity';
import { PolicyFormData } from '../entities/policy-builder-state.entity';

@Injectable()
export class PolicyTemplateService {
  private readonly templatesFile = path.join(process.cwd(), '..', 'data', 'policy-templates.json');
  private templates: PolicyTemplate[] = [];
  private initialized = false;

  /**
   * Initialize templates from file
   */
  private async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      await fs.mkdir(path.dirname(this.templatesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.templatesFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.templates = (parsed.templates || []).map((t: any) => ({
          ...t,
          createdAt: new Date(t.createdAt),
          updatedAt: new Date(t.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          // File doesn't exist, use default templates
          this.templates = this.getDefaultTemplates();
          await this.saveTemplates();
        } else {
          throw readError;
        }
      }
      this.initialized = true;
    } catch (error) {
      console.error('Error loading policy templates:', error);
      // Fallback to default templates
      this.templates = this.getDefaultTemplates();
      this.initialized = true;
    }
  }

  /**
   * Save templates to file
   */
  private async saveTemplates(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.templatesFile), { recursive: true });
      await fs.writeFile(
        this.templatesFile,
        JSON.stringify({ templates: this.templates }, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('Error saving policy templates:', error);
    }
  }

  /**
   * Find all templates with optional filters
   */
  async findAll(filters?: {
    category?: string;
    policyType?: 'rbac' | 'abac';
    tags?: string[];
  }): Promise<PolicyTemplate[]> {
    await this.initialize();

    let filtered = [...this.templates];

    if (filters?.category) {
      filtered = filtered.filter(t => t.category === filters.category);
    }

    if (filters?.policyType) {
      filtered = filtered.filter(t => t.policyType === filters.policyType);
    }

    if (filters?.tags && filters.tags.length > 0) {
      filtered = filtered.filter(t =>
        filters.tags!.some(tag => t.tags.includes(tag))
      );
    }

    return filtered;
  }

  /**
   * Find one template by ID
   */
  async findOne(id: string): Promise<PolicyTemplate> {
    await this.initialize();

    const template = this.templates.find(t => t.id === id);
    if (!template) {
      throw new NotFoundException(`Template with ID "${id}" not found`);
    }

    return template;
  }

  /**
   * Apply template to get form data
   */
  applyTemplate(template: PolicyTemplate): PolicyFormData {
    return { ...template.template };
  }

  /**
   * Get default templates
   */
  private getDefaultTemplates(): PolicyTemplate[] {
    const now = new Date();
    return [
      {
        id: 'template-department-match',
        name: 'Department Match',
        description: 'Users can access resources from their own department',
        category: 'department-based',
        policyType: 'abac',
        template: {
          name: 'Department Match Policy',
          description: 'Users can access resources from their own department',
          version: '1.0.0',
          status: 'draft' as any,
          effect: 'allow' as any,
          priority: 100,
          conditions: [
            {
              id: 'cond-1',
              attribute: 'subject.department',
              operator: 'equals',
              value: '{{resource.department}}',
            },
          ],
        },
        exampleJson: JSON.stringify({
          id: 'abac-department-match',
          name: 'Department Match Policy',
          description: 'Users can access resources from their own department',
          effect: 'allow',
          priority: 100,
          conditions: [
            {
              attribute: 'subject.department',
              operator: 'equals',
              value: '{{resource.department}}',
            },
          ],
        }, null, 2),
        tags: ['department', 'abac', 'basic'],
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'template-role-based-access',
        name: 'Role-Based Access',
        description: 'Admins have full access, viewers have read-only access',
        category: 'role-based',
        policyType: 'rbac',
        template: {
          name: 'Role-Based Access Policy',
          description: 'Admins have full access, viewers have read-only access',
          version: '1.0.0',
          status: 'draft' as any,
          effect: 'allow' as any,
          rules: [
            {
              id: 'rule-admin',
              description: 'Admin users have full access',
              effect: 'allow' as any,
              role: 'admin',
            },
            {
              id: 'rule-viewer',
              description: 'Viewers can access public resources',
              effect: 'allow' as any,
              role: 'viewer',
              resourceSensitivity: ['public'],
            },
          ],
        },
        exampleJson: JSON.stringify({
          name: 'Role-Based Access Policy',
          version: '1.0.0',
          rules: [
            {
              id: 'rule-admin',
              description: 'Admin users have full access',
              effect: 'allow',
              conditions: {
                'subject.role': 'admin',
              },
            },
            {
              id: 'rule-viewer',
              description: 'Viewers can access public resources',
              effect: 'allow',
              conditions: {
                'subject.role': 'viewer',
                'resource.sensitivity': 'public',
              },
            },
          ],
        }, null, 2),
        tags: ['role', 'rbac', 'basic'],
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'template-project-access',
        name: 'Project Access',
        description: 'Users can access resources from projects they have access to',
        category: 'project-based',
        policyType: 'abac',
        template: {
          name: 'Project Access Policy',
          description: 'Users can access resources from projects they have access to',
          version: '1.0.0',
          status: 'draft' as any,
          effect: 'allow' as any,
          priority: 150,
          conditions: [
            {
              id: 'cond-1',
              attribute: 'subject.projectAccess',
              operator: 'contains',
              value: '{{resource.project}}',
            },
          ],
        },
        exampleJson: JSON.stringify({
          id: 'abac-project-access',
          name: 'Project Access Policy',
          description: 'Users can access resources from projects they have access to',
          effect: 'allow',
          priority: 150,
          conditions: [
            {
              attribute: 'subject.projectAccess',
              operator: 'contains',
              value: '{{resource.project}}',
            },
          ],
        }, null, 2),
        tags: ['project', 'abac', 'basic'],
        createdAt: now,
        updatedAt: now,
      },
    ];
  }
}
