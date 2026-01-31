import { PolicyFormData } from './policy-builder-state.entity';

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  category: 'department-based' | 'role-based' | 'project-based' | 'compliance' | 'custom';
  policyType: 'rbac' | 'abac';
  template: PolicyFormData; // Pre-filled form data
  exampleJson: string; // Example JSON output
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
}
