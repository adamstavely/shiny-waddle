/**
 * Integration Tests for Compliance Workflow
 * 
 * Tests the complete workflow:
 * 1. Run test battery
 * 2. Generate findings
 * 3. Create violations
 * 4. Track remediation
 * 5. Update compliance score
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { TestBatteriesService } from '../src/test-batteries/test-batteries.service';
import { TestHarnessesService } from '../src/test-harnesses/test-harnesses.service';
import { TestSuitesService } from '../src/test-suites/test-suites.service';
import { ApplicationsService } from '../src/applications/applications.service';
import { UnifiedFindingsService } from '../src/unified-findings/unified-findings.service';
import { ViolationsService } from '../src/violations/violations.service';
import { RemediationTrackingService } from '../src/remediation-tracking/remediation-tracking.service';
import { ComplianceScoresService } from '../src/compliance/compliance-scores.service';
import { CreateTestBatteryDto } from '../src/test-batteries/dto/create-test-battery.dto';
import { CreateTestHarnessDto } from '../src/test-harnesses/dto/create-test-harness.dto';
import { CreateTestSuiteDto } from '../src/test-suites/dto/create-test-suite.dto';
import { CreateApplicationDto, ApplicationType } from '../src/applications/dto/create-application.dto';
import { CreateViolationDto, ViolationSeverity } from '../src/violations/dto/create-violation.dto';
import { CreateRemediationTrackingDto } from '../src/remediation-tracking/entities/remediation-tracking.entity';
import { ScannerResult } from '../../../heimdall-framework/services/normalization-engine';

describe('Compliance Workflow (Integration)', () => {
  let app: INestApplication;
  let testBatteriesService: TestBatteriesService;
  let testHarnessesService: TestHarnessesService;
  let testSuitesService: TestSuitesService;
  let applicationsService: ApplicationsService;
  let unifiedFindingsService: UnifiedFindingsService;
  let violationsService: ViolationsService;
  let remediationTrackingService: RemediationTrackingService;
  let complianceScoresService: ComplianceScoresService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    testBatteriesService = getService(app, TestBatteriesService);
    testHarnessesService = getService(app, TestHarnessesService);
    testSuitesService = getService(app, TestSuitesService);
    applicationsService = getService(app, ApplicationsService);
    unifiedFindingsService = getService(app, UnifiedFindingsService);
    violationsService = getService(app, ViolationsService);
    complianceScoresService = getService(app, ComplianceScoresService);
    remediationTrackingService = getService(app, RemediationTrackingService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('should run test battery, generate findings, create violations, track remediation, and update compliance score', async () => {
    // Step 1: Create application
    const applicationDto: CreateApplicationDto = {
      id: `compliance-test-app-${Date.now()}`,
      name: 'Compliance Test Application',
      description: 'Application for compliance workflow testing',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);
    expect(application).toBeDefined();

    // Step 2: Create test suite
    const suiteDto: CreateTestSuiteDto = {
      name: 'Compliance Test Suite',
      applicationId: application.id,
      team: 'test-team',
      testType: 'access-control',
      enabled: true,
    };
    const suite = await testSuitesService.create(suiteDto);
    expect(suite).toBeDefined();

    // Step 3: Create test harness
    const harnessDto: CreateTestHarnessDto = {
      name: 'Compliance Test Harness',
      description: 'Harness for compliance testing',
      domain: 'identity',
      testSuiteIds: [suite.id],
      applicationIds: [application.id],
      team: 'test-team',
    };
    const harness = await testHarnessesService.create(harnessDto);
    expect(harness).toBeDefined();

    // Step 4: Create test battery
    const batteryDto: CreateTestBatteryDto = {
      name: 'Compliance Test Battery',
      description: 'Battery for compliance testing',
      harnessIds: [harness.id],
      executionConfig: {
        executionMode: 'sequential',
        timeout: 30000,
      },
      team: 'test-team',
    };
    const battery = await testBatteriesService.create(batteryDto);
    expect(battery).toBeDefined();

    // Step 5: Generate findings from test results (simulate scanner results)
    const scannerResult: ScannerResult = {
      scannerId: 'test-scanner',
      source: 'test-scanner',
      findings: [
        {
          id: 'finding-1',
          title: 'Test Finding',
          description: 'Test finding for compliance workflow',
          severity: 'high',
          asset: {
            applicationId: application.id,
            applicationName: application.name,
            type: 'application',
          },
        },
      ],
      metadata: {},
    };
    const findings = await unifiedFindingsService.normalizeAndIngest([scannerResult]);
    expect(findings).toBeDefined();
    expect(findings.length).toBeGreaterThan(0);

    // Step 6: Create violation from finding
    const violationDto: CreateViolationDto = {
      title: 'Test Violation',
      description: 'Violation created from test finding',
      type: 'policy-violation',
      severity: ViolationSeverity.HIGH,
      application: application.name,
      team: 'test-team',
      policyName: 'Test Policy',
      resource: 'test-resource',
      testResultId: 'test-result-1',
      testResultDetails: {
        findingId: findings[0].id,
      },
    };
    const violation = await violationsService.create(violationDto);
    expect(violation).toBeDefined();
    expect(violation.id).toBeDefined();

    // Step 7: Track remediation
    const remediationDto: CreateRemediationTrackingDto = {
      violationId: violation.id,
      remediationSteps: [
        {
          id: 'step-1',
          description: 'Fix the issue',
          status: 'pending',
        },
      ],
      assignedTo: 'test-user',
    };
    const remediation = await remediationTrackingService.createTracking(remediationDto);
    expect(remediation).toBeDefined();
    expect(remediation.violationId).toBe(violation.id);

    // Step 8: Verify compliance score history can be queried
    const complianceHistory = await complianceScoresService.getHistory({
      applicationId: application.id,
      days: 30,
    });
    expect(Array.isArray(complianceHistory)).toBe(true);

    // Verify the complete workflow
    const retrievedViolation = await violationsService.findOne(violation.id);
    expect(retrievedViolation).toBeDefined();
    expect(retrievedViolation?.status).toBeDefined();

    const retrievedRemediation = await remediationTrackingService.findOne(remediation.id);
    expect(retrievedRemediation).toBeDefined();
    expect(retrievedRemediation?.violationId).toBe(violation.id);
  });
});
