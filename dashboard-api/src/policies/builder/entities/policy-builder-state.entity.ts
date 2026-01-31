import { PolicyType, PolicyStatus, PolicyEffect, RBACRule, ABACCondition } from '../../dto/create-policy.dto';

export interface PolicyBuilderState {
  id: string;
  policyId?: string; // If editing existing policy
  currentStep: number;
  totalSteps: number;
  policyType: 'rbac' | 'abac';
  formData: PolicyFormData;
  jsonData: string; // Current JSON representation
  validationErrors: ValidationError[];
  lastSynced: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyFormData {
  // Basic Info
  name: string;
  description?: string;
  version: string;
  status: PolicyStatus;
  effect: PolicyEffect;
  
  // RBAC-specific
  rules?: RBACRuleFormData[];
  
  // ABAC-specific
  priority?: number;
  conditions?: ABACConditionFormData[];
  
  // Metadata
  applicationId?: string;
  templateUsed?: string;
}

export interface RBACRuleFormData {
  id: string;
  description?: string;
  effect: PolicyEffect;
  role: string;
  resourceType?: string;
  resourceSensitivity?: string[];
  contextConditions?: Record<string, any>;
}

export interface ABACConditionFormData {
  id: string;
  attribute: string; // e.g., "subject.department"
  operator: 'equals' | 'notEquals' | 'in' | 'notIn' | 'contains' | 'greaterThan' | 'lessThan' | 'regex';
  value: string | string[] | number;
  logicalOperator?: 'AND' | 'OR';
}

export interface ValidationError {
  field: string;
  message: string;
  severity: 'error' | 'warning';
  code?: string;
}
