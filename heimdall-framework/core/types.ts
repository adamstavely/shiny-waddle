/**
 * Type definitions for the Heimdall framework
 */

import { RuntimeTestConfig } from './runtime-config';

export interface TestConfiguration {
  accessControlConfig: AccessControlConfig;
  datasetHealthConfig: DatasetHealthConfig;
  reportingConfig: ReportingConfig;
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

export interface DatasetHealthConfig {
  privacyMetrics?: PrivacyMetric[];
  statisticalTests?: StatisticalTest[];
}

export interface ReportingConfig {
  outputFormat: 'json' | 'html' | 'junit';
  outputPath?: string;
  includeDetails?: boolean;
}

// Test Domain Union - all supported test domains
export type TestDomain =
  | 'api_security'
  | 'platform_config'
  | 'identity'
  | 'data_contracts'
  | 'salesforce'
  | 'elastic'
  | 'idp_platform';

// Test Type Union - all supported test types
export type TestType = 
  | 'access-control' 
  | 'dataset-health'
  | 'rls-cls'
  | 'network-policy'
  | 'dlp'
  | 'api-gateway'
  | 'distributed-systems'
  | 'api-security'
  | 'data-pipeline'
  | 'data-contract'
  | 'salesforce-config'
  | 'salesforce-security'
  | 'salesforce-experience-cloud'
  | 'elastic-config'
  | 'elastic-security'
  | 'k8s-security'
  | 'k8s-workload'
  | 'idp-compliance'
  | 'servicenow-config'
  | 'environment-config'
  | 'secrets-management'
  | 'config-drift'
  | 'environment-policies';

// Baseline configuration for platform config test suites
export interface BaselineConfig {
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes' | 'servicenow';
  environment: string; // production, staging, development
  config: Record<string, any>; // Platform-specific config structure
  version: string;
}

// TestSuite - collection of tests (no configuration, tests are pre-made)
export interface TestSuite {
  id: string;
  name: string;
  application: string; // Application ID - infrastructure comes from application.infrastructure
  team: string;
  testType: TestType; // All tests in suite must match this type
  domain: TestDomain; // Domain for this test suite
  testIds: string[]; // References to Test entities
  description?: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  /**
   * Runtime configuration that overrides hardcoded values in tests
   * This allows tests to be environment-agnostic
   */
  runtimeConfig?: RuntimeTestConfig;
  /**
   * Baseline configuration for platform config test suites
   * Contains the desired state configuration that tests validate against
   */
  baselineConfig?: BaselineConfig;
  // REMOVED: testConfigurationIds - infrastructure comes from application.infrastructure
}

export interface TestResult {
  testType: TestType;
  testName: string;
  passed: boolean;
  details: any;
  timestamp: Date;
  error?: string;
  testId?: string;
  testVersion?: number;
  policyId?: string; // Changed from policyIds - 1:1 relationship
}

// Test Version History
export interface TestVersion {
  version: number;
  testConfiguration: any; // Snapshot of test config at this version
  changedBy?: string;
  changeReason?: string;
  changedAt: Date;
  changes?: string[]; // List of what changed
}

// Base Test Interface
export interface BaseTest {
  id: string;
  name: string;
  description?: string;
  testType: TestType;
  domain: TestDomain; // Domain for this test
  version: number;
  versionHistory?: TestVersion[];
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  lastModifiedBy?: string;
}

// Access Control Test - 1:1 with Policy
export interface AccessControlTest extends BaseTest {
  testType: 'access-control';
  
  // 1:1 relationship with Policy (required for policy-based tests)
  policyId: string; // Changed from policyIds: string[] - exactly one policy
  
  // Test inputs and expectations
  inputs: {
    subject?: {
      role?: string;
      attributes?: Record<string, any>;
    };
    resource: Resource;
    context?: Context;
    action?: string;
  };
  expected: {
    allowed: boolean; // Changed from expectedDecision
    reason?: string;
  };
}

// Dataset Health Test - optional policy relationship
export interface DatasetHealthTest extends BaseTest {
  testType: 'dataset-health';
  policyId?: string; // Optional - not all tests validate policies
  dataset: Dataset;
  privacyThresholds?: PrivacyThreshold[];
  statisticalFidelityTargets?: StatisticalFidelityTarget[];
  expected: {
    compliant: boolean;
    metrics?: Record<string, number>;
  };
}

// RLS/CLS Test - references application infrastructure
export interface RLSCLSTest extends BaseTest {
  testType: 'rls-cls';
  policyId?: string; // Optional
  applicationId: string; // References application with database infrastructure
  databaseId?: string; // Which database in application.infrastructure.databases
  testQuery: TestQuery;
  expected: {
    rlsEnabled: boolean;
    clsEnabled?: boolean;
    coverage?: number;
  };
  maskingRules?: Array<{
    table: string;
    column: string;
    maskingType: 'partial' | 'full' | 'hash' | 'redact';
    condition?: string;
  }>;
}

// Network Policy Test
export interface NetworkPolicyTest extends BaseTest {
  testType: 'network-policy';
  policyId?: string; // Optional
  applicationId?: string; // References application with network infrastructure
  source: string;
  target: string;
  protocol: 'tcp' | 'udp' | 'icmp' | 'all';
  port?: number;
  expected: {
    allowed: boolean;
  };
}

// DLP Test - one per pattern/rule
export interface DLPTest extends BaseTest {
  testType: 'dlp';
  // Pattern-based test
  pattern?: DLPPattern;
  testData?: any; // Sample data to test against pattern
  expectedDetection?: boolean; // Should pattern detect or not?
  // OR Bulk export test
  bulkExportType?: 'csv' | 'json' | 'excel' | 'api';
  bulkExportLimit?: number;
  testRecordCount?: number; // Test with this many records
  expectedBlocked?: boolean; // Should it block if over limit?
  // OR PII detection rule test
  piiDetectionRule?: {
    fieldName: string;
    pattern: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  };
  // OR Custom check test
  customCheck?: {
    name: string;
    condition: string;
    description?: string;
  };
}

// API Gateway Test - 1:1 with Policy
export interface APIGatewayTest extends BaseTest {
  testType: 'api-gateway';
  policyId: string; // Required - 1:1 with gateway policy
  applicationId?: string; // References application with API gateway infrastructure
  gatewayType: 'aws-api-gateway' | 'azure-api-management' | 'kong' | 'istio' | 'envoy';
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  policyType?: 'authentication' | 'authorization' | 'rate-limit' | 'transformation' | 'caching';
  expected: {
    allowed?: boolean;
    rateLimited?: boolean;
    authenticated?: boolean;
    [key: string]: any;
  };
}

// Distributed Systems Test
export interface DistributedSystemsTest extends BaseTest {
  testType: 'distributed-systems';
  distributedTestType: 'multi-region' | 'policy-consistency' | 'policy-synchronization';
  applicationId?: string; // References application with distributed systems infrastructure
  
  // Multi-Region Test Configuration
  multiRegionConfig?: {
    regions: string[]; // Region IDs to test
    executionMode?: 'parallel' | 'sequential';
    timeout?: number;
    user?: {
      id: string;
      attributes?: Record<string, any>;
    };
    resource?: {
      id: string;
      type?: string;
      attributes?: Record<string, any>;
    };
    action?: string;
    expectedResult?: boolean;
  };
  
  // Policy Consistency Test Configuration
  policyConsistencyConfig?: {
    regions: string[]; // Region IDs to check
    policyIds?: string[]; // Specific policies to check, or all if not specified
    checkTypes?: ('version' | 'configuration' | 'evaluation')[];
  };
  
  // Policy Synchronization Test Configuration
  policySyncConfig?: {
    regions: string[]; // Region IDs to test
    policyId?: string; // Specific policy to test, or all if not specified
    testScenarios?: ('update-propagation' | 'sync-timing' | 'sync-failure-recovery')[];
  };
}

// API Security Enhanced Test
export interface APISecurityTest extends BaseTest {
  testType: 'api-security';
  // API Versioning test
  apiVersion?: {
    version: string;
    endpoint: string;
    deprecated?: boolean;
    deprecationDate?: Date;
    sunsetDate?: Date;
  };
  // OR Gateway Policy test
  gatewayPolicy?: {
    gatewayType: 'aws-api-gateway' | 'azure-api-management' | 'kong' | 'istio' | 'envoy';
    endpoint: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    policyId: string;
    policyType: 'authentication' | 'authorization' | 'rate-limit' | 'transformation' | 'caching';
    route?: { path: string; method: string; target: string };
  };
  // OR Webhook test
  webhook?: {
    endpoint: string;
    authentication: { type: 'signature' | 'token' | 'oauth2'; method: string };
    encryption: { enabled: boolean; method?: string };
    rateLimiting?: { maxRequests: number; windowSeconds: number };
  };
  // OR GraphQL test
  graphql?: {
    endpoint: string;
    schema: string;
    testType: 'depth' | 'complexity' | 'introspection' | 'full';
    maxDepth?: number;
    maxComplexity?: number;
    introspectionEnabled?: boolean;
  };
  // OR API Contract test
  apiContract?: {
    version: string;
    schema: any;
    endpoints?: Array<{
      path: string;
      method: string;
      parameters?: Array<{
        name: string;
        in: 'query' | 'header' | 'path' | 'body';
        type: string;
        required: boolean;
      }>;
    }>;
  };
  expectedResult?: any;
}

// Data Pipeline Test
export interface DataPipelineTest extends BaseTest {
  testType: 'data-pipeline';
  pipelineType: 'etl' | 'streaming' | 'batch' | 'real-time';
  dataSource?: {
    type: 'database' | 'api' | 'file' | 'stream';
    connectionString?: string;
  };
  dataDestination?: {
    type: 'database' | 'data-warehouse' | 'data-lake' | 'api';
    connectionString?: string;
  };
  expectedResult?: any;
}

// Platform Config Test - validates platform configuration against baseline
export interface PlatformConfigTest extends BaseTest {
  testType: 'salesforce-config' | 'salesforce-security' | 'elastic-config' | 'elastic-security' | 'k8s-security' | 'k8s-workload' | 'idp-compliance' | 'servicenow-config';
  domain: 'platform_config' | 'salesforce' | 'elastic' | 'idp_platform';
  
  // Platform-specific test fields
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes' | 'servicenow';
  
  // Validation rule expression (e.g., "encryption.fieldEncryption.enabled === true")
  check: string;
  
  // Severity level
  severity: 'critical' | 'high' | 'medium' | 'low';
  
  // True if derived from baseline config, false if custom rule
  autoGenerated: boolean;
  
  // Optional: Reference to baseline config section (e.g., "encryption.fieldEncryption.enabled")
  configPath?: string;
  
  // Expected result
  expected?: {
    passed: boolean;
    message?: string;
  };
}

// Salesforce Experience Cloud Test - for Salesforce Experience Cloud security testing
export interface SalesforceExperienceCloudTest extends BaseTest {
  testType: 'salesforce-experience-cloud';
  domain: 'salesforce' | 'api_security';
  
  // Test subtype (guest-access, authenticated-access, graphql, etc.)
  testSubtype: 'guest-access' | 'authenticated-access' | 'graphql' | 'self-registration' | 'record-lists' | 'home-urls' | 'object-access' | 'full-audit';
  
  // Configuration reference (config stored in runtimeConfig)
  configId?: string; // Optional reference to Salesforce Experience Cloud config
  
  // Expected result
  expected?: {
    passed: boolean;
    maxSeverity?: 'critical' | 'high' | 'medium' | 'low';
    maxFindings?: number;
  };
}

// Discriminated union for Test
export type Test =
  | AccessControlTest
  | DatasetHealthTest
  | RLSCLSTest
  | NetworkPolicyTest
  | DLPTest
  | APIGatewayTest
  | DistributedSystemsTest
  | APISecurityTest
  | DataPipelineTest
  | PlatformConfigTest
  | SalesforceExperienceCloudTest;

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
    contracts: number;
    datasetHealth: number;
  };
  testResults: TestResult[];
  lastUpdated: Date;
}

// RLS/CLS Testing Types
export interface DatabaseConfig {
  type: 'postgresql' | 'mysql' | 'mssql' | 'oracle' | 'sqlite';
  connectionString?: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
}

export interface RLSCoverage {
  database: string;
  totalTables: number;
  tablesWithRLS: number;
  tablesWithoutRLS: string[];
  coveragePercentage: number;
  policies: Array<{
    table: string;
    policyName: string;
    policyDefinition: string;
    enabled: boolean;
  }>;
  details?: Record<string, any>; // For custom validation results
  validationResults?: {
    minRLSCoverageMet?: boolean;
    minRLSCoverage?: number;
    actualCoverage?: number;
    requiredPoliciesMet?: boolean;
    missingPolicies?: string[];
  };
}

export interface CLSCoverage {
  database: string;
  totalTables: number;
  tablesWithCLS: number;
  tablesWithoutCLS: string[];
  coveragePercentage: number;
  policies: Array<{
    table: string;
    column: string;
    policyType: 'masking' | 'encryption' | 'redaction';
    policyDefinition: string;
    enabled: boolean;
  }>;
  details?: Record<string, any>; // For custom validation results
  validationResults?: {
    minCLSCoverageMet?: boolean;
    minCLSCoverage?: number;
    actualCoverage?: number;
  };
}

export interface DynamicMaskingRule {
  table: string;
  column: string;
  maskingType: 'partial' | 'full' | 'hash' | 'tokenize';
  pattern?: string;
  applicableRoles: string[];
}

export interface CrossTenantIsolationTest {
  tenant1: string;
  tenant2: string;
  testQueries: TestQuery[];
  isolationVerified: boolean;
  violations: string[];
  details?: Record<string, any>; // For custom validation results
}

// Network Micro-Segmentation Types
export interface NetworkSegment {
  id: string;
  name: string;
  cidr?: string;
  services: string[];
  allowedConnections: string[];
  deniedConnections: string[];
}

export interface FirewallRule {
  id: string;
  name: string;
  source: string;
  destination: string;
  protocol: 'tcp' | 'udp' | 'icmp' | 'all';
  port?: number;
  action: 'allow' | 'deny';
  enabled: boolean;
}

export interface NetworkPolicyTestResult {
  source: string;
  target: string;
  protocol: string;
  port: number;
  expectedAllowed: boolean;
  actualAllowed: boolean;
  policyApplied?: string;
}

export interface IdentityVerification {
  userId: string;
  method: 'password' | 'mfa' | 'certificate' | 'biometric';
  verified: boolean;
  timestamp: Date;
}

// DLP Types
export interface DLPPattern {
  name: string;
  type: 'regex' | 'keyword' | 'data-classification' | 'custom';
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface DataExfiltrationTest {
  user: User;
  operation: 'export' | 'download' | 'api-call' | 'query';
  dataSize: number;
  detected: boolean;
  pattern?: DLPPattern;
}

export interface BulkExportTest {
  user: User;
  exportType: 'csv' | 'json' | 'excel' | 'api';
  recordCount: number;
  allowed: boolean;
  reason?: string;
}

export interface DataOperation {
  type: 'read' | 'write' | 'export' | 'delete';
  resource: Resource;
  data: any;
}

// Policy Validation Types
export interface PolicyConflict {
  policy1: string;
  policy2: string;
  conflictType: 'overlap' | 'contradiction' | 'priority';
  description: string;
  affectedResources: string[];
}

export interface PolicyCoverage {
  totalResources: number;
  resourcesWithPolicies: number;
  resourcesWithoutPolicies: string[];
  coveragePercentage: number;
  gaps: Array<{
    resource: string;
    resourceType: string;
    recommendedPolicy: string;
  }>;
}

export interface PolicySimulation {
  policy: ABACPolicy;
  testCases: Array<{
    name: string;
    request: any;
    expectedResult: boolean;
    simulatedResult: boolean;
    match: boolean;
  }>;
  overallMatch: boolean;
}

// API Gateway Types
export interface APIGatewayPolicy {
  id: string;
  name: string;
  endpoint: string;
  method: string;
  rules: Array<{
    condition: string;
    action: 'allow' | 'deny' | 'rate-limit';
    config?: Record<string, any>;
  }>;
}

export interface APIRequest {
  endpoint: string;
  method: string;
  headers: Record<string, string>;
  body?: any;
  user?: User;
}

export interface RateLimitTest {
  endpoint: string;
  requests: number;
  timeWindow: number; // seconds
  limit: number;
  actualRequests: number;
  blocked: boolean;
  blockedAt?: number;
}

export interface ServiceAuthTest {
  source: string;
  target: string;
  authMethod: 'mtls' | 'jwt' | 'api-key' | 'oauth2';
  authenticated: boolean;
  certificateValid?: boolean;
  tokenValid?: boolean;
}

// NIST 800-207 Types
export interface ZTAPillar {
  name: 'identity' | 'device' | 'network' | 'application' | 'data';
  score: number;
  maxScore: number;
  controls: Array<{
    id: string;
    name: string;
    description: string;
    status: 'compliant' | 'non-compliant' | 'partial';
    evidence: string[];
  }>;
}

export interface ZTAAssessment {
  id: string;
  timestamp: Date;
  pillars: ZTAPillar[];
  overallScore: number;
  gaps: string[];
  recommendations: string[];
}

export interface ComplianceAssessment {
  framework: 'NIST-800-207';
  assessment: ZTAAssessment;
  compliancePercentage: number;
  compliant: boolean;
}

// Identity Provider Types
export interface ADGroupTest {
  user: User;
  group: string;
  membership: boolean;
  expectedMembership: boolean;
  match: boolean;
}

export interface OktaPolicyTest {
  policyId: string;
  policyName: string;
  synchronized: boolean;
  lastSync: Date;
  violations: string[];
}

export interface AzureADConditionalAccessPolicy {
  id: string;
  name: string;
  conditions: {
    users?: string[];
    applications?: string[];
    locations?: string[];
    devicePlatforms?: string[];
  };
  grantControls: {
    requireMfa?: boolean;
    requireCompliantDevice?: boolean;
  };
}

export interface GCPIAMBinding {
  resource: string;
  role: string;
  members: string[];
  condition?: {
    title: string;
    expression: string;
  };
}

// CI/CD Security Gates Types
export interface IACScanResult {
  files: string[];
  findings: Array<{
    file: string;
    line: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
    type: 'missing-policy' | 'overly-permissive' | 'hardcoded-secret' | 'insecure-config';
    description: string;
    recommendation: string;
  }>;
  passed: boolean;
}

export interface ContainerScanResult {
  image: string;
  vulnerabilities: Array<{
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    package: string;
    version: string;
    description: string;
  }>;
  passed: boolean;
}

export interface K8sRBACTest {
  namespace: string;
  role: string;
  rules: Array<{
    resources: string[];
    verbs: string[];
    allowed: boolean;
    reason?: string;
  }>;
  passed: boolean;
}

export interface SecurityGateConfig {
  severityThreshold: 'critical' | 'high' | 'medium' | 'low';
  failOnThreshold: boolean;
  maxFindings?: number;
  requirePolicies: boolean;
  scanIAC: boolean;
  scanContainers: boolean;
  validateK8sRBAC: boolean;
}

export interface SecurityGateResult {
  passed: boolean;
  gates: Array<{
    name: string;
    passed: boolean;
    details: any;
  }>;
  findings: any[];
  riskScore: number;
  message: string;
}

export interface PullRequest {
  id: string;
  number: number;
  branch: string;
  baseBranch: string;
  files: string[];
  author: string;
}

// Test Harness Entity
export interface TestHarness {
  id: string;
  name: string;
  description: string;
  domain: TestDomain; // Required: all suites in harness must have this domain
  testSuiteIds: string[]; // Many-to-many: suites can be in multiple harnesses (all must match domain)
  applicationIds: string[]; // Assigned to applications
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Test Battery Entity
export interface TestBattery {
  id: string;
  name: string;
  description?: string;
  harnessIds: string[]; // Collection of test harnesses
  executionConfig?: BatteryExecutionConfig;
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface BatteryExecutionConfig {
  executionMode: 'parallel' | 'sequential';
  timeout?: number;
  stopOnFailure?: boolean;
}

export interface TestBatteryResult {
  batteryId: string;
  harnessResults: Array<{
    harnessId: string;
    results: TestResult[];
  }>;
  overallPassed: boolean;
  timestamp: Date;
}

// ABAC Correctness Configuration Types
// These types are used for ABAC correctness testing within access control test suites

export interface ABACAttribute {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  source: 'ldap' | 'database' | 'api' | 'jwt' | 'custom';
  validation: ABACValidationRule[];
  freshness?: {
    maxAge: number;
    unit: 'seconds' | 'minutes' | 'hours';
  };
}

export interface ABACValidationRule {
  type: 'required' | 'format' | 'range' | 'enum' | 'regex' | 'custom';
  value?: any;
  message?: string;
}

export interface ABACPerformanceTestConfig {
  policies: ABACPolicy[];
  testRequests: Array<{
    subject: {
      id: string;
      attributes: Record<string, any>;
    };
    resource: {
      id: string;
      type: string;
      attributes: Record<string, any>;
    };
    context: {
      ipAddress?: string;
      timeOfDay?: string;
      location?: string;
      device?: string;
      additionalAttributes?: Record<string, any>;
    };
    action?: string;
  }>;
  loadConfig?: {
    concurrentRequests: number;
    duration: number; // milliseconds
  };
}

export interface ABACCorrectnessConfig {
  attributes?: ABACAttribute[];
  policies?: ABACPolicy[];
  resourceTypes?: string[];
  userRoles?: string[];
  performanceConfig?: ABACPerformanceTestConfig;
  conflictResolutionStrategy?: 'priority' | 'deny-override' | 'allow-override' | 'first-match';
}

// Access Control Test Suite Configuration
// This interface represents the configuration shape used by validators
// It extends the base test suite pattern with access-control specific fields
export interface AccessControlTestSuiteConfig {
  name: string;
  application: string;
  team: string;
  testType: 'access-control';
  userRoles: string[];
  resources: Resource[];
  contexts: Context[];
  expectedDecisions?: Record<string, boolean>;
  runtimeConfig?: RuntimeTestConfig;
  abacCorrectnessConfig?: ABACCorrectnessConfig;
}

// Data Behavior Config - for query analysis and data behavior testing
export interface DataBehaviorConfig {
  queryInterceptor?: boolean;
  enableQueryLogging?: boolean;
  piiDetectionRules?: Array<{
    field: string;
    pattern: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
}

// Re-export ServiceMeshConfig from service-mesh-integration for convenience
export { ServiceMeshConfig } from '../services/service-mesh-integration';

