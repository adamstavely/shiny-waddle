export enum PolicyType {
  RBAC = 'rbac',
  ABAC = 'abac',
}

export enum PolicyStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  DEPRECATED = 'deprecated',
}

export enum PolicyEffect {
  ALLOW = 'allow',
  DENY = 'deny',
}

export interface RBACRule {
  id: string;
  description?: string;
  effect: PolicyEffect;
  conditions: Record<string, any>;
}

export interface ABACCondition {
  attribute: string;
  operator: string;
  value: string;
  logicalOperator?: string;
}

export class CreatePolicyDto {
  name: string;
  description?: string;
  type: PolicyType;
  version: string;
  status?: PolicyStatus;
  effect?: PolicyEffect;
  priority?: number;
  rules?: RBACRule[];
  conditions?: ABACCondition[];
  applicationId?: string;
}

