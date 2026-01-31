import { PolicyType } from './create-policy.dto';

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  type: PolicyType;
  category: 'department' | 'role' | 'resource' | 'compliance' | 'custom';
  tags: string[];
  template: {
    name: string;
    description?: string;
    type: PolicyType;
    version: string;
    status?: string;
    effect?: string;
    priority?: number;
    rules?: any[];
    conditions?: any[];
  };
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  usageCount?: number;
}

export class CreateTemplateDto {
  name: string;
  description: string;
  type: PolicyType;
  category: 'department' | 'role' | 'resource' | 'compliance' | 'custom';
  tags?: string[];
  template: {
    name: string;
    description?: string;
    type: PolicyType;
    version: string;
    status?: string;
    effect?: string;
    priority?: number;
    rules?: any[];
    conditions?: any[];
  };
}

export class UpdateTemplateDto {
  name?: string;
  description?: string;
  category?: 'department' | 'role' | 'resource' | 'compliance' | 'custom';
  tags?: string[];
  template?: {
    name?: string;
    description?: string;
    type?: PolicyType;
    version?: string;
    status?: string;
    effect?: string;
    priority?: number;
    rules?: any[];
    conditions?: any[];
  };
}
