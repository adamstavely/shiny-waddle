/**
 * Type definitions for the Sentinel framework
 */

export interface TestConfiguration {
  userSimulationConfig: UserSimulationConfig;
  accessControlConfig: AccessControlConfig;
  dataBehaviorConfig: DataBehaviorConfig;
  contractTestConfig: ContractTestConfig;
  datasetHealthConfig: DatasetHealthConfig;
  reportingConfig: ReportingConfig;
}

export interface UserSimulationConfig {
  roles: string[];
  attributes: Record<string, any>;
  workspaceMemberships?: WorkspaceMembership[];
}

export interface AccessControlConfig {
  pdpEndpoint?: string;
  policyEngine?: 'opa' | 'cedar' | 'custom';
  cacheDecisions?: boolean;
  policyMode?: 'rbac' | 'abac' | 'hybrid'; // Support RBAC, ABAC, or both
  abacPolicies?: ABACPolicy[];
}

export interface ABACPolicy {
  id: string;
  name: string;
  description: string;
  effect: 'allow' | 'deny';
  conditions: ABACCondition[];
  priority?: number; // Higher priority policies are evaluated first
}

export interface ABACCondition {
  attribute: string; // e.g., "subject.department", "resource.dataClassification"
  operator: 'equals' | 'notEquals' | 'in' | 'notIn' | 'greaterThan' | 'lessThan' | 'contains' | 'startsWith' | 'endsWith' | 'regex';
  value: any;
  logicalOperator?: 'AND' | 'OR'; // For combining multiple conditions
}

export interface DataBehaviorConfig {
  queryInterceptor?: boolean;
  enableQueryLogging?: boolean;
  piiDetectionRules?: PiiDetectionRule[];
}

export interface ContractTestConfig {
  contractDefinitionsPath?: string;
  autoGenerateTests?: boolean;
}

export interface DatasetHealthConfig {
  privacyMetrics?: PrivacyMetric[];
  statisticalTests?: StatisticalTest[];
}

export interface ReportingConfig {
  outputFormat: 'json' | 'html' | 'junit';
  outputPath?: string;
  includeDetails?: boolean;
}

export interface TestSuite {
  name: string;
  application: string;
  team: string;
  includeAccessControlTests: boolean;
  includeDataBehaviorTests: boolean;
  includeContractTests: boolean;
  includeDatasetHealthTests: boolean;
  userRoles: string[];
  resources: Resource[];
  contexts: Context[];
  expectedDecisions?: Record<string, boolean>;
  testQueries?: TestQuery[];
  allowedFields?: Record<string, string[]>;
  requiredFilters?: Record<string, Filter[]>;
  disallowedJoins?: Record<string, string[]>;
  contracts?: Contract[];
  datasets?: Dataset[];
  privacyThresholds?: PrivacyThreshold[];
  statisticalFidelityTargets?: StatisticalFidelityTarget[];
}

export interface TestResult {
  testType: 'access-control' | 'data-behavior' | 'contract' | 'dataset-health';
  testName: string;
  passed: boolean;
  details: any;
  timestamp: Date;
  error?: string;
}

export interface User {
  id: string;
  email: string;
  role: 'admin' | 'researcher' | 'analyst' | 'viewer';
  attributes: Record<string, any>; // ABAC attributes: department, clearanceLevel, projectAccess, etc.
  workspaceMemberships?: WorkspaceMembership[];
  // ABAC-specific attributes
  abacAttributes?: {
    department?: string;
    clearanceLevel?: 'low' | 'medium' | 'high' | 'top-secret';
    projectAccess?: string[];
    dataClassification?: string[];
    location?: string;
    employmentType?: 'full-time' | 'part-time' | 'contractor';
    certifications?: string[];
    [key: string]: any;
  };
}

export interface WorkspaceMembership {
  workspaceId: string;
  role: 'owner' | 'editor' | 'viewer';
}

export interface Resource {
  id: string;
  type: string;
  attributes: Record<string, any>;
  sensitivity?: 'public' | 'internal' | 'confidential' | 'restricted';
  // ABAC-specific attributes
  abacAttributes?: {
    dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted' | 'top-secret';
    owner?: string;
    project?: string;
    department?: string;
    region?: string;
    requiresCertification?: string[];
    minClearanceLevel?: 'low' | 'medium' | 'high' | 'top-secret';
    [key: string]: any;
  };
}

export interface Context {
  ipAddress?: string;
  timeOfDay?: string;
  location?: string;
  device?: string;
  additionalAttributes?: Record<string, any>;
}

export interface TestQuery {
  name: string;
  sql?: string;
  apiEndpoint?: string;
  httpMethod?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  requestBody?: any;
}

export interface Filter {
  field: string;
  operator: '=' | '!=' | '>' | '<' | '>=' | '<=' | 'IN' | 'NOT IN' | 'LIKE';
  value: any;
}

export interface Contract {
  name: string;
  dataOwner: string;
  requirements: ContractRequirement[];
  machineReadable?: boolean;
  schema?: any;
}

export interface ContractRequirement {
  id: string;
  description: string;
  type: 'field-restriction' | 'aggregation-requirement' | 'join-restriction' | 'export-restriction';
  rule: any;
  enforcement: 'hard' | 'soft';
}

export interface Dataset {
  name: string;
  type: 'raw' | 'masked' | 'synthetic';
  schema: any;
  recordCount?: number;
  piiFields?: string[];
}

export interface PrivacyThreshold {
  metric: string;
  threshold: number;
  operator: '>' | '<' | '>=' | '<=' | '=';
}

export interface StatisticalFidelityTarget {
  field: string;
  metric: 'mean' | 'median' | 'stddev' | 'distribution';
  targetValue?: number;
  tolerance?: number;
}

export interface PiiDetectionRule {
  fieldPattern: string;
  piiType: 'email' | 'ssn' | 'phone' | 'credit-card' | 'ip-address' | 'custom';
  regex?: string;
}

export interface PrivacyMetric {
  name: string;
  type: 'k-anonymity' | 'l-diversity' | 't-closeness' | 'differential-privacy';
  threshold: number;
}

export interface StatisticalTest {
  name: string;
  type: 'chi-square' | 'kolmogorov-smirnov' | 'mann-whitney' | 'custom';
  parameters?: Record<string, any>;
}

export interface ComplianceScore {
  application: string;
  team: string;
  overallScore: number;
  scoresByCategory: {
    accessControl: number;
    dataBehavior: number;
    contracts: number;
    datasetHealth: number;
  };
  testResults: TestResult[];
  lastUpdated: Date;
}

