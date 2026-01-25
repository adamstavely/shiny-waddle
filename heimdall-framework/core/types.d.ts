export interface TestConfiguration {
    accessControlConfig: AccessControlConfig;
    dataBehaviorConfig: DataBehaviorConfig;
    datasetHealthConfig: DatasetHealthConfig;
    reportingConfig: ReportingConfig;
}
export interface AccessControlConfig {
    pdpEndpoint?: string;
    policyEngine?: 'opa' | 'cedar' | 'custom';
    cacheDecisions?: boolean;
    policyMode?: 'rbac' | 'abac' | 'hybrid';
    abacPolicies?: ABACPolicy[];
}
export interface ABACPolicy {
    id: string;
    name: string;
    description: string;
    effect: 'allow' | 'deny';
    conditions: ABACCondition[];
    priority?: number;
}
export interface ABACCondition {
    attribute: string;
    operator: 'equals' | 'notEquals' | 'in' | 'notIn' | 'greaterThan' | 'lessThan' | 'contains' | 'startsWith' | 'endsWith' | 'regex';
    value: any;
    logicalOperator?: 'AND' | 'OR';
}
export interface DataBehaviorConfig {
    queryInterceptor?: boolean;
    enableQueryLogging?: boolean;
    piiDetectionRules?: PiiDetectionRule[];
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
    includeDatasetHealthTests: boolean;
    userRoles: string[];
    resources: Resource[];
    contexts: Context[];
    expectedDecisions?: Record<string, boolean>;
    testQueries?: TestQuery[];
    allowedFields?: Record<string, string[]>;
    requiredFilters?: Record<string, Filter[]>;
    disallowedJoins?: Record<string, string[]>;
    datasets?: Dataset[];
    privacyThresholds?: PrivacyThreshold[];
    statisticalFidelityTargets?: StatisticalFidelityTarget[];
}
export interface TestResult {
    testType: 'access-control' | 'data-behavior' | 'dataset-health';
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
    attributes: Record<string, any>;
    workspaceMemberships?: WorkspaceMembership[];
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
        dataBehavior: number;
        contracts: number;
        datasetHealth: number;
    };
    testResults: TestResult[];
    lastUpdated: Date;
}
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
}
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
export interface NetworkPolicyTest {
    source: string;
    target: string;
    protocol: string;
    port: number;
    expectedAllowed: boolean;
    actualAllowed: boolean;
    policyApplied?: string;
}
export interface IdentityLifecycleEvent {
    type: 'onboarding' | 'role-change' | 'offboarding' | 'credential-rotation' | 'mfa-enforcement';
    userId: string;
    timestamp: Date;
    details: Record<string, any>;
}
export interface PAMRequest {
    userId: string;
    resource: string;
    reason: string;
    duration: number;
    approver?: string;
    emergency?: boolean;
}
export interface PAMWorkflow {
    id: string;
    name: string;
    steps: Array<{
        type: 'approval' | 'notification' | 'validation';
        config: Record<string, any>;
    }>;
}
export interface IdentityVerification {
    userId: string;
    method: 'password' | 'mfa' | 'certificate' | 'biometric';
    verified: boolean;
    timestamp: Date;
}
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
    timeWindow: number;
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
