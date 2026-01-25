/**
 * Seed script to create test definitions, suites, harnesses, and batteries
 * for the four new domains: Data Contracts, Salesforce, Elastic, IDP/K8s
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { getDomainFromTestType } from '../../../heimdall-framework/core/domain-mapping';
import { TestType } from '../../../heimdall-framework/core/types';

interface TestDefinition {
  id: string;
  name: string;
  description: string;
  testType: TestType;
  domain: string;
  version: number;
  versionHistory: any[];
  createdAt: string;
  updatedAt: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  params?: Record<string, any>;
}

interface TestSuiteDefinition {
  id: string;
  name: string;
  applicationId: string;
  team: string;
  testType: string;
  domain: string;
  testIds: string[];
  description?: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  status: string;
  testCount: number;
  score: number;
}

interface TestHarnessDefinition {
  id: string;
  name: string;
  description: string;
  domain: string;
  testType?: string;
  testSuiteIds: string[];
  applicationIds: string[];
  team?: string;
  createdAt: string;
  updatedAt: string;
}

interface TestBatteryDefinition {
  id: string;
  name: string;
  description?: string;
  harnessIds: string[];
  executionConfig?: {
    executionMode: 'parallel' | 'sequential';
    timeout?: number;
    stopOnFailure?: boolean;
  };
  team?: string;
  createdAt: string;
  updatedAt: string;
}

async function seedNewDomainTests() {
  const dataDir = path.join(process.cwd(), 'data');
  const now = new Date().toISOString();

  // Load existing tests
  const testsFile = path.join(dataDir, 'tests.json');
  let existingTests: TestDefinition[] = [];
  try {
    const data = await fs.readFile(testsFile, 'utf-8');
    existingTests = JSON.parse(data);
  } catch (error: any) {
    if (error.code !== 'ENOENT') throw error;
  }

  // Generate test definitions
  const newTests: TestDefinition[] = [];

  // ===== DATA CONTRACTS TESTS (7 tests) =====
  const dataContractTests = [
    {
      name: 'Schema matches registered data contract',
      description: 'Validates that the runtime schema matches the registered data contract schema',
      testType: 'data-contract' as TestType,
      severity: 'high' as const,
      params: { contractId: 'string' },
    },
    {
      name: 'Required fields present',
      description: 'Ensures all required fields from the contract are present in the data',
      testType: 'data-contract' as TestType,
      severity: 'high' as const,
    },
    {
      name: 'Enum values within contract',
      description: 'Validates that enum field values match the contract definition',
      testType: 'data-contract' as TestType,
      severity: 'medium' as const,
    },
    {
      name: 'Contract version in sync with runtime schema',
      description: 'Checks that the contract version matches the runtime schema version',
      testType: 'data-contract' as TestType,
      severity: 'high' as const,
    },
    {
      name: 'PII fields match contract classification',
      description: 'Verifies that PII field classifications match the contract specification',
      testType: 'data-contract' as TestType,
      severity: 'critical' as const,
    },
    {
      name: 'Contract quality SLA respected',
      description: 'Validates that data quality metrics meet the contract SLA requirements',
      testType: 'data-contract' as TestType,
      severity: 'medium' as const,
    },
    {
      name: 'Null rate within contract threshold',
      description: 'Checks that null value rates are within the contract-defined thresholds',
      testType: 'data-contract' as TestType,
      severity: 'medium' as const,
    },
  ];

  dataContractTests.forEach((test, index) => {
    newTests.push({
      id: `test.data_contracts.${test.name.toLowerCase().replace(/\s+/g, '_')}`,
      name: test.name,
      description: test.description,
      testType: test.testType,
      domain: getDomainFromTestType(test.testType),
      version: 1,
      versionHistory: [],
      createdAt: now,
      updatedAt: now,
      severity: test.severity,
      params: test.params,
    });
  });

  // ===== SALESFORCE TESTS (10 tests) =====
  const salesforceTests = [
    // Config Drift
    { name: 'Metadata matches baseline', testType: 'salesforce-config' as TestType, severity: 'high' as const },
    { name: 'Profiles match expected permissions', testType: 'salesforce-config' as TestType, severity: 'high' as const },
    { name: 'Validation rules match baseline', testType: 'salesforce-config' as TestType, severity: 'medium' as const },
    { name: 'Flows match baseline', testType: 'salesforce-config' as TestType, severity: 'medium' as const },
    { name: 'Connected apps match baseline', testType: 'salesforce-config' as TestType, severity: 'high' as const },
    // Security
    { name: 'MFA enforced for all users', testType: 'salesforce-security' as TestType, severity: 'critical' as const },
    { name: 'Guest user access restricted', testType: 'salesforce-security' as TestType, severity: 'high' as const },
    { name: 'Org wide defaults secure', testType: 'salesforce-security' as TestType, severity: 'high' as const },
    { name: 'Excessive permissions detected', testType: 'salesforce-security' as TestType, severity: 'high' as const },
    { name: 'Inactive users deactivated', testType: 'salesforce-security' as TestType, severity: 'medium' as const },
    { name: 'Critical perms limited to admins', testType: 'salesforce-security' as TestType, severity: 'critical' as const },
  ];

  salesforceTests.forEach((test) => {
    newTests.push({
      id: `test.salesforce.${test.name.toLowerCase().replace(/\s+/g, '_')}`,
      name: `Salesforce ${test.name}`,
      description: `Salesforce test: ${test.name}`,
      testType: test.testType,
      domain: getDomainFromTestType(test.testType),
      version: 1,
      versionHistory: [],
      createdAt: now,
      updatedAt: now,
      severity: test.severity,
    });
  });

  // ===== ELASTIC TESTS (13 tests) =====
  const elasticTests = [
    // Config Drift
    { name: 'Cluster settings match baseline', testType: 'elastic-config' as TestType, severity: 'high' as const },
    { name: 'Index templates match baseline', testType: 'elastic-config' as TestType, severity: 'high' as const },
    { name: 'ILM policies match baseline', testType: 'elastic-config' as TestType, severity: 'medium' as const },
    { name: 'Ingest pipelines match baseline', testType: 'elastic-config' as TestType, severity: 'medium' as const },
    { name: 'Snapshots configured for critical indices', testType: 'elastic-config' as TestType, severity: 'high' as const },
    // Security
    { name: 'Security features enabled', testType: 'elastic-security' as TestType, severity: 'critical' as const },
    { name: 'TLS enabled internode', testType: 'elastic-security' as TestType, severity: 'critical' as const },
    { name: 'TLS enabled HTTP', testType: 'elastic-security' as TestType, severity: 'critical' as const },
    { name: 'Anonymous access disabled', testType: 'elastic-security' as TestType, severity: 'critical' as const },
    { name: 'Roles match baseline', testType: 'elastic-security' as TestType, severity: 'high' as const },
    { name: 'Excessive privileges detected', testType: 'elastic-security' as TestType, severity: 'high' as const },
    { name: 'API keys scoped and valid', testType: 'elastic-security' as TestType, severity: 'high' as const },
    // Data Protection
    { name: 'Sensitive indices protected', testType: 'elastic-security' as TestType, severity: 'critical' as const },
    { name: 'Snapshots encrypted and in compliant region', testType: 'elastic-security' as TestType, severity: 'high' as const },
    { name: 'Multi-tenant index patterns isolated', testType: 'elastic-security' as TestType, severity: 'high' as const },
  ];

  elasticTests.forEach((test) => {
    newTests.push({
      id: `test.elastic.${test.name.toLowerCase().replace(/\s+/g, '_')}`,
      name: `Elastic ${test.name}`,
      description: `Elastic test: ${test.name}`,
      testType: test.testType,
      domain: getDomainFromTestType(test.testType),
      version: 1,
      versionHistory: [],
      createdAt: now,
      updatedAt: now,
      severity: test.severity,
    });
  });

  // ===== IDP/K8S TESTS (25+ tests) =====
  const idpTests = [
    // Control Plane
    { name: 'API server authn enabled', testType: 'k8s-security' as TestType, severity: 'critical' as const },
    { name: 'API server audit logging enabled', testType: 'k8s-security' as TestType, severity: 'high' as const },
    { name: 'etcd encrypted at rest', testType: 'k8s-security' as TestType, severity: 'critical' as const },
    { name: 'Control plane TLS enforced', testType: 'k8s-security' as TestType, severity: 'critical' as const },
    { name: 'CIS controls pass', testType: 'k8s-security' as TestType, severity: 'high' as const },
    // Namespace Isolation
    { name: 'Namespace has resource quotas', testType: 'k8s-workload' as TestType, severity: 'high' as const },
    { name: 'Namespace has limit ranges', testType: 'k8s-workload' as TestType, severity: 'high' as const },
    { name: 'Tenant namespaces isolated', testType: 'k8s-workload' as TestType, severity: 'critical' as const },
    { name: 'Pod security standards enforced', testType: 'k8s-workload' as TestType, severity: 'high' as const },
    // Network
    { name: 'Default deny network policies present', testType: 'k8s-security' as TestType, severity: 'high' as const },
    { name: 'Mesh mTLS enabled', testType: 'k8s-security' as TestType, severity: 'critical' as const },
    { name: 'Ingress restricts external exposure', testType: 'k8s-security' as TestType, severity: 'high' as const },
    { name: 'Egress policies enforced', testType: 'k8s-security' as TestType, severity: 'medium' as const },
    // Workload
    { name: 'No privileged containers', testType: 'k8s-workload' as TestType, severity: 'critical' as const },
    { name: 'No hostpath mounts without approval', testType: 'k8s-workload' as TestType, severity: 'high' as const },
    { name: 'Run as non-root enforced', testType: 'k8s-workload' as TestType, severity: 'high' as const },
    { name: 'Capabilities dropped', testType: 'k8s-workload' as TestType, severity: 'high' as const },
    { name: 'Liveness readiness probes configured', testType: 'k8s-workload' as TestType, severity: 'medium' as const },
    // Supply Chain
    { name: 'Images from trusted registry only', testType: 'idp-compliance' as TestType, severity: 'high' as const },
    { name: 'Images signed and verified', testType: 'idp-compliance' as TestType, severity: 'high' as const },
    { name: 'No latest tag in prod', testType: 'idp-compliance' as TestType, severity: 'medium' as const },
    { name: 'Base images on allowlist', testType: 'idp-compliance' as TestType, severity: 'high' as const },
    { name: 'Vulnerability policy respected', testType: 'idp-compliance' as TestType, severity: 'critical' as const },
    // Secrets
    { name: 'No plaintext secrets in configmaps or env', testType: 'k8s-security' as TestType, severity: 'critical' as const },
    { name: 'Secrets stored in approved backend', testType: 'k8s-security' as TestType, severity: 'high' as const },
    { name: 'Secrets mounted least privilege', testType: 'k8s-security' as TestType, severity: 'high' as const },
    // Observability
    { name: 'Cert manager issuers configured', testType: 'idp-compliance' as TestType, severity: 'medium' as const },
    { name: 'Ingress TLS required', testType: 'idp-compliance' as TestType, severity: 'high' as const },
    { name: 'Workloads emit structured logs', testType: 'idp-compliance' as TestType, severity: 'medium' as const },
    { name: 'Workloads have standard labels', testType: 'idp-compliance' as TestType, severity: 'low' as const },
    { name: 'Metrics and traces exported', testType: 'idp-compliance' as TestType, severity: 'medium' as const },
    // Golden Path
    { name: 'Service conforms to golden template', testType: 'idp-compliance' as TestType, severity: 'high' as const },
    { name: 'Required sidecars present', testType: 'idp-compliance' as TestType, severity: 'high' as const },
    { name: 'Backstage catalog entry in sync', testType: 'idp-compliance' as TestType, severity: 'low' as const },
  ];

  idpTests.forEach((test) => {
    newTests.push({
      id: `test.idp.${test.name.toLowerCase().replace(/\s+/g, '_')}`,
      name: `K8s/IDP ${test.name}`,
      description: `Kubernetes/IDP test: ${test.name}`,
      testType: test.testType,
      domain: getDomainFromTestType(test.testType),
      version: 1,
      versionHistory: [],
      createdAt: now,
      updatedAt: now,
      severity: test.severity,
    });
  });

  // Combine with existing tests
  const allTests = [...existingTests, ...newTests];
  await fs.writeFile(testsFile, JSON.stringify(allTests, null, 2), 'utf-8');
  console.log(`✓ Created ${newTests.length} new test definitions`);

  // Create test suites
  const suitesFile = path.join(dataDir, 'test-suites.json');
  let existingSuites: TestSuiteDefinition[] = [];
  try {
    const data = await fs.readFile(suitesFile, 'utf-8');
    existingSuites = JSON.parse(data);
  } catch (error: any) {
    if (error.code !== 'ENOENT') throw error;
  }

  const newSuites: TestSuiteDefinition[] = [];
  const testMap = new Map(newTests.map(t => [t.id, t]));

  // Data Contracts Suites (3)
  const dataContractSuiteTests = [
    newTests.filter(t => t.domain === 'data_contracts' && (t.name.includes('Schema') || t.name.includes('Required') || t.name.includes('Enum') || t.name.includes('version'))),
    newTests.filter(t => t.domain === 'data_contracts' && (t.name.includes('PII') || t.name.includes('classification'))),
    newTests.filter(t => t.domain === 'data_contracts' && (t.name.includes('SLA') || t.name.includes('null'))),
  ];

  const dataContractSuiteNames = [
    'Data Contract – Schema Conformance',
    'Data Contract – Security & Classification Alignment',
    'Data Contract – Quality & SLAs',
  ];

  dataContractSuiteTests.forEach((suiteTests, index) => {
    if (suiteTests.length > 0) {
      newSuites.push({
        id: `suite.data_contracts.${index + 1}`,
        name: dataContractSuiteNames[index],
        applicationId: 'default',
        team: 'Data Platform',
        testType: 'data-contract',
        domain: 'data_contracts',
        testIds: suiteTests.map(t => t.id),
        description: dataContractSuiteNames[index],
        enabled: true,
        createdAt: now,
        updatedAt: now,
        status: 'pending',
        testCount: suiteTests.length,
        score: 0,
      });
    }
  });

  // Salesforce Suites (2)
  const salesforceConfigTests = newTests.filter(t => t.testType === 'salesforce-config');
  const salesforceSecurityTests = newTests.filter(t => t.testType === 'salesforce-security');

  if (salesforceConfigTests.length > 0) {
    newSuites.push({
      id: 'suite.salesforce.config_baseline',
      name: 'Salesforce – Configuration Baseline',
      applicationId: 'default',
      team: 'Salesforce Team',
      testType: 'salesforce-config',
      domain: 'salesforce',
      testIds: salesforceConfigTests.map(t => t.id),
      description: 'Salesforce configuration baseline tests',
      enabled: true,
      createdAt: now,
      updatedAt: now,
      status: 'pending',
      testCount: salesforceConfigTests.length,
      score: 0,
    });
  }

  if (salesforceSecurityTests.length > 0) {
    newSuites.push({
      id: 'suite.salesforce.security',
      name: 'Salesforce – Security Posture',
      applicationId: 'default',
      team: 'Salesforce Team',
      testType: 'salesforce-security',
      domain: 'salesforce',
      testIds: salesforceSecurityTests.map(t => t.id),
      description: 'Salesforce security posture tests',
      enabled: true,
      createdAt: now,
      updatedAt: now,
      status: 'pending',
      testCount: salesforceSecurityTests.length,
      score: 0,
    });
  }

  // Elastic Suites (3)
  const elasticConfigTests = newTests.filter(t => t.testType === 'elastic-config');
  const elasticSecurityTests = newTests.filter(t => t.testType === 'elastic-security' && !t.name.includes('Sensitive') && !t.name.includes('Snapshots') && !t.name.includes('Multi-tenant'));
  const elasticDataProtectionTests = newTests.filter(t => t.testType === 'elastic-security' && (t.name.includes('Sensitive') || t.name.includes('Snapshots') || t.name.includes('Multi-tenant')));

  if (elasticConfigTests.length > 0) {
    newSuites.push({
      id: 'suite.elastic.config',
      name: 'Elastic – Cluster Baseline Config',
      applicationId: 'default',
      team: 'Infrastructure',
      testType: 'elastic-config',
      domain: 'elastic',
      testIds: elasticConfigTests.map(t => t.id),
      description: 'Elastic cluster baseline configuration tests',
      enabled: true,
      createdAt: now,
      updatedAt: now,
      status: 'pending',
      testCount: elasticConfigTests.length,
      score: 0,
    });
  }

  if (elasticSecurityTests.length > 0) {
    newSuites.push({
      id: 'suite.elastic.security',
      name: 'Elastic – Security Posture',
      applicationId: 'default',
      team: 'Infrastructure',
      testType: 'elastic-security',
      domain: 'elastic',
      testIds: elasticSecurityTests.map(t => t.id),
      description: 'Elastic security posture tests',
      enabled: true,
      createdAt: now,
      updatedAt: now,
      status: 'pending',
      testCount: elasticSecurityTests.length,
      score: 0,
    });
  }

  if (elasticDataProtectionTests.length > 0) {
    newSuites.push({
      id: 'suite.elastic.data_protection',
      name: 'Elastic – Data Protection & Tenancy',
      applicationId: 'default',
      team: 'Infrastructure',
      testType: 'elastic-security',
      domain: 'elastic',
      testIds: elasticDataProtectionTests.map(t => t.id),
      description: 'Elastic data protection and tenancy tests',
      enabled: true,
      createdAt: now,
      updatedAt: now,
      status: 'pending',
      testCount: elasticDataProtectionTests.length,
      score: 0,
    });
  }

  // IDP/K8s Suites (8)
  const idpControlPlaneTests = newTests.filter(t => t.testType === 'k8s-security' && (t.name.includes('API server') || t.name.includes('etcd') || t.name.includes('Control plane') || t.name.includes('CIS')));
  const idpTenantIsolationTests = newTests.filter(t => t.testType === 'k8s-workload' && (t.name.includes('Namespace') || t.name.includes('Tenant') || t.name.includes('Pod security')));
  const idpNetworkTests = newTests.filter(t => t.testType === 'k8s-security' && (t.name.includes('Network') || t.name.includes('Mesh') || t.name.includes('Ingress') || t.name.includes('Egress')));
  const idpWorkloadTests = newTests.filter(t => t.testType === 'k8s-workload' && (t.name.includes('privileged') || t.name.includes('hostpath') || t.name.includes('non-root') || t.name.includes('Capabilities') || t.name.includes('probes')));
  const idpSupplyChainTests = newTests.filter(t => t.testType === 'idp-compliance' && (t.name.includes('Images') || t.name.includes('signed') || t.name.includes('latest') || t.name.includes('Vulnerability')));
  const idpSecretsTests = newTests.filter(t => t.testType === 'k8s-security' && t.name.includes('Secrets'));
  const idpObservabilityTests = newTests.filter(t => t.testType === 'idp-compliance' && (t.name.includes('Cert') || t.name.includes('TLS') || t.name.includes('logs') || t.name.includes('labels') || t.name.includes('Metrics')));
  const idpGoldenPathTests = newTests.filter(t => t.testType === 'idp-compliance' && (t.name.includes('golden') || t.name.includes('sidecars') || t.name.includes('Backstage')));

  const idpSuiteGroups = [
    { name: 'IDP – Cluster & Control Plane Hardening', tests: idpControlPlaneTests },
    { name: 'IDP – Tenant Isolation & Resource Governance', tests: idpTenantIsolationTests },
    { name: 'IDP – Network & Service Mesh Security', tests: idpNetworkTests },
    { name: 'IDP – Workload Hardening & Health', tests: idpWorkloadTests },
    { name: 'IDP – Supply Chain & Image Hygiene', tests: idpSupplyChainTests },
    { name: 'IDP – Secrets & Config Hygiene', tests: idpSecretsTests },
    { name: 'IDP – Platform Services & Observability', tests: idpObservabilityTests },
    { name: 'IDP – Golden Path Compliance', tests: idpGoldenPathTests },
  ];

  idpSuiteGroups.forEach((group, index) => {
    if (group.tests.length > 0) {
      const primaryTestType = group.tests[0].testType;
      newSuites.push({
        id: `suite.idp.${index + 1}`,
        name: group.name,
        applicationId: 'default',
        team: 'Platform',
        testType: primaryTestType,
        domain: 'idp_platform',
        testIds: group.tests.map(t => t.id),
        description: group.name,
        enabled: true,
        createdAt: now,
        updatedAt: now,
        status: 'pending',
        testCount: group.tests.length,
        score: 0,
      });
    }
  });

  const allSuites = [...existingSuites, ...newSuites];
  await fs.writeFile(suitesFile, JSON.stringify(allSuites, null, 2), 'utf-8');
  console.log(`✓ Created ${newSuites.length} new test suites`);

  // Create test harnesses
  const harnessesFile = path.join(dataDir, 'test-harnesses.json');
  let existingHarnesses: TestHarnessDefinition[] = [];
  try {
    const data = await fs.readFile(harnessesFile, 'utf-8');
    existingHarnesses = JSON.parse(data);
  } catch (error: any) {
    if (error.code !== 'ENOENT') throw error;
  }

  const newHarnesses: TestHarnessDefinition[] = [];
  const suiteMap = new Map(newSuites.map(s => [s.id, s]));

  // Data Contracts Harnesses (2)
  const dataContractSuites = newSuites.filter(s => s.domain === 'data_contracts');
  if (dataContractSuites.length >= 2) {
    newHarnesses.push({
      id: 'h_data_contracts_preprod_validation',
      name: 'Data Contracts Preprod Validation',
      description: 'Data contract validation harness for pre-production environments',
      domain: 'data_contracts',
      testType: 'data-contract',
      testSuiteIds: [dataContractSuites[0].id],
      applicationIds: [],
      team: 'Data Platform',
      createdAt: now,
      updatedAt: now,
    });

    newHarnesses.push({
      id: 'h_data_contracts_prod_drift',
      name: 'Data Contracts Prod Drift',
      description: 'Data contract drift detection harness for production',
      domain: 'data_contracts',
      testType: 'data-contract',
      testSuiteIds: dataContractSuites.slice(1).map(s => s.id),
      applicationIds: [],
      team: 'Data Platform',
      createdAt: now,
      updatedAt: now,
    });
  }

  // Salesforce Harnesses (2)
  const salesforceSuites = newSuites.filter(s => s.domain === 'salesforce');
  if (salesforceSuites.length >= 2) {
    newHarnesses.push({
      id: 'h_salesforce_metadata_scan',
      name: 'Salesforce Metadata Scan',
      description: 'Salesforce metadata baseline scanning harness',
      domain: 'salesforce',
      testType: 'salesforce-config',
      testSuiteIds: [salesforceSuites[0].id],
      applicationIds: [],
      team: 'Salesforce Team',
      createdAt: now,
      updatedAt: now,
    });

    newHarnesses.push({
      id: 'h_salesforce_security_scan',
      name: 'Salesforce Security Scan',
      description: 'Salesforce security posture scanning harness',
      domain: 'salesforce',
      testType: 'salesforce-security',
      testSuiteIds: [salesforceSuites[1].id],
      applicationIds: [],
      team: 'Salesforce Team',
      createdAt: now,
      updatedAt: now,
    });
  }

  // Elastic Harnesses (2)
  const elasticSuites = newSuites.filter(s => s.domain === 'elastic');
  if (elasticSuites.length >= 2) {
    newHarnesses.push({
      id: 'h_elastic_config_scan',
      name: 'Elastic Config Scan',
      description: 'Elastic cluster configuration baseline scanning harness',
      domain: 'elastic',
      testType: 'elastic-config',
      testSuiteIds: [elasticSuites[0].id],
      applicationIds: [],
      team: 'Infrastructure',
      createdAt: now,
      updatedAt: now,
    });

    newHarnesses.push({
      id: 'h_elastic_security_scan',
      name: 'Elastic Security Scan',
      description: 'Elastic security posture scanning harness',
      domain: 'elastic',
      testType: 'elastic-security',
      testSuiteIds: elasticSuites.slice(1).map(s => s.id),
      applicationIds: [],
      team: 'Infrastructure',
      createdAt: now,
      updatedAt: now,
    });
  }

  // IDP/K8s Harnesses (3)
  const idpSuites = newSuites.filter(s => s.domain === 'idp_platform');
  if (idpSuites.length >= 3) {
    newHarnesses.push({
      id: 'h_idp_cluster_scan',
      name: 'IDP Cluster Scan',
      description: 'IDP/K8s cluster and control plane scanning harness',
      domain: 'idp_platform',
      testType: 'k8s-security',
      testSuiteIds: idpSuites.filter(s => s.name.includes('Cluster') || s.name.includes('Control')).map(s => s.id),
      applicationIds: [],
      team: 'Platform',
      createdAt: now,
      updatedAt: now,
    });

    newHarnesses.push({
      id: 'h_idp_workload_hardening_scan',
      name: 'IDP Workload Hardening Scan',
      description: 'IDP/K8s workload hardening and security scanning harness',
      domain: 'idp_platform',
      testType: 'k8s-workload',
      testSuiteIds: idpSuites.filter(s => s.name.includes('Workload') || s.name.includes('Tenant') || s.name.includes('Secrets')).map(s => s.id),
      applicationIds: [],
      team: 'Platform',
      createdAt: now,
      updatedAt: now,
    });

    newHarnesses.push({
      id: 'h_idp_golden_path_scan',
      name: 'IDP Golden Path Scan',
      description: 'IDP golden path compliance scanning harness',
      domain: 'idp_platform',
      testType: 'idp-compliance',
      testSuiteIds: idpSuites.filter(s => s.name.includes('Golden') || s.name.includes('Supply') || s.name.includes('Observability')).map(s => s.id),
      applicationIds: [],
      team: 'Platform',
      createdAt: now,
      updatedAt: now,
    });
  }

  const allHarnesses = [...existingHarnesses, ...newHarnesses];
  await fs.writeFile(harnessesFile, JSON.stringify(allHarnesses, null, 2), 'utf-8');
  console.log(`✓ Created ${newHarnesses.length} new test harnesses`);

  // Create test batteries
  const batteriesFile = path.join(dataDir, 'test-batteries.json');
  let existingBatteries: TestBatteryDefinition[] = [];
  try {
    const data = await fs.readFile(batteriesFile, 'utf-8');
    existingBatteries = JSON.parse(data);
  } catch (error: any) {
    if (error.code !== 'ENOENT') throw error;
  }

  const newBatteries: TestBatteryDefinition[] = [];
  const harnessMap = new Map(newHarnesses.map(h => [h.id, h]));

  // Data Contracts Batteries (2)
  const dataContractHarnesses = newHarnesses.filter(h => h.domain === 'data_contracts');
  if (dataContractHarnesses.length > 0) {
    newBatteries.push({
      id: 'b_data_contracts_only',
      name: 'Data Contracts Only',
      description: 'Battery containing all data contract tests',
      harnessIds: dataContractHarnesses.map(h => h.id),
      executionConfig: {
        executionMode: 'parallel',
        stopOnFailure: false,
      },
      team: 'Data Platform',
      createdAt: now,
      updatedAt: now,
    });

    newBatteries.push({
      id: 'b_data_governance_full',
      name: 'Data Governance Full',
      description: 'Full data governance battery including contracts and related tests',
      harnessIds: dataContractHarnesses.map(h => h.id),
      executionConfig: {
        executionMode: 'sequential',
        stopOnFailure: true,
      },
      team: 'Data Platform',
      createdAt: now,
      updatedAt: now,
    });
  }

  // Salesforce Batteries (2)
  const salesforceHarnesses = newHarnesses.filter(h => h.domain === 'salesforce');
  if (salesforceHarnesses.length > 0) {
    newBatteries.push({
      id: 'b_salesforce_full_compliance',
      name: 'Salesforce Full Compliance',
      description: 'Complete Salesforce compliance battery',
      harnessIds: salesforceHarnesses.map(h => h.id),
      executionConfig: {
        executionMode: 'parallel',
        stopOnFailure: false,
      },
      team: 'Salesforce Team',
      createdAt: now,
      updatedAt: now,
    });

    newBatteries.push({
      id: 'b_salesforce_monthly_security',
      name: 'Salesforce Monthly Security',
      description: 'Monthly Salesforce security scanning battery',
      harnessIds: salesforceHarnesses.filter(h => h.id.includes('security')).map(h => h.id),
      executionConfig: {
        executionMode: 'sequential',
        timeout: 3600000,
        stopOnFailure: false,
      },
      team: 'Salesforce Team',
      createdAt: now,
      updatedAt: now,
    });
  }

  // Elastic Batteries (2)
  const elasticHarnesses = newHarnesses.filter(h => h.domain === 'elastic');
  if (elasticHarnesses.length > 0) {
    newBatteries.push({
      id: 'b_elastic_full_compliance',
      name: 'Elastic Full Compliance',
      description: 'Complete Elastic compliance battery',
      harnessIds: elasticHarnesses.map(h => h.id),
      executionConfig: {
        executionMode: 'parallel',
        stopOnFailure: false,
      },
      team: 'Infrastructure',
      createdAt: now,
      updatedAt: now,
    });

    newBatteries.push({
      id: 'b_elastic_security_daily',
      name: 'Elastic Security Daily',
      description: 'Daily Elastic security scanning battery',
      harnessIds: elasticHarnesses.filter(h => h.id.includes('security')).map(h => h.id),
      executionConfig: {
        executionMode: 'sequential',
        timeout: 1800000,
        stopOnFailure: false,
      },
      team: 'Infrastructure',
      createdAt: now,
      updatedAt: now,
    });
  }

  // IDP/K8s Batteries (3)
  const idpHarnesses = newHarnesses.filter(h => h.domain === 'idp_platform');
  if (idpHarnesses.length > 0) {
    newBatteries.push({
      id: 'b_idp_full_compliance',
      name: 'IDP Full Compliance',
      description: 'Complete IDP/K8s compliance battery',
      harnessIds: idpHarnesses.map(h => h.id),
      executionConfig: {
        executionMode: 'parallel',
        stopOnFailure: false,
      },
      team: 'Platform',
      createdAt: now,
      updatedAt: now,
    });

    newBatteries.push({
      id: 'b_idp_security_daily',
      name: 'IDP Security Daily',
      description: 'Daily IDP/K8s security scanning battery',
      harnessIds: idpHarnesses.filter(h => h.id.includes('cluster') || h.id.includes('workload')).map(h => h.id),
      executionConfig: {
        executionMode: 'sequential',
        timeout: 3600000,
        stopOnFailure: false,
      },
      team: 'Platform',
      createdAt: now,
      updatedAt: now,
    });

    newBatteries.push({
      id: 'b_idp_golden_path_weekly',
      name: 'IDP Golden Path Weekly',
      description: 'Weekly IDP golden path compliance battery',
      harnessIds: idpHarnesses.filter(h => h.id.includes('golden')).map(h => h.id),
      executionConfig: {
        executionMode: 'sequential',
        timeout: 1800000,
        stopOnFailure: true,
      },
      team: 'Platform',
      createdAt: now,
      updatedAt: now,
    });
  }

  const allBatteries = [...existingBatteries, ...newBatteries];
  await fs.writeFile(batteriesFile, JSON.stringify(allBatteries, null, 2), 'utf-8');
  console.log(`✓ Created ${newBatteries.length} new test batteries`);

  console.log('\n✅ Seeding complete!');
  console.log(`- Tests: ${newTests.length}`);
  console.log(`- Suites: ${newSuites.length}`);
  console.log(`- Harnesses: ${newHarnesses.length}`);
  console.log(`- Batteries: ${newBatteries.length}`);
}

// Run if executed directly
if (require.main === module) {
  seedNewDomainTests()
    .then(() => {
      console.log('Seed script completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Seed script failed:', error);
      process.exit(1);
    });
}

export { seedNewDomainTests };

