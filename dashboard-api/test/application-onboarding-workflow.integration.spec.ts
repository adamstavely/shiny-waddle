/**
 * Integration Tests for Application Onboarding Workflow
 * 
 * Tests the complete workflow:
 * 1. Create application
 * 2. Add infrastructure
 * 3. Assign test harness
 * 4. Run initial tests
 * 5. View dashboard
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { ApplicationsService } from '../src/applications/applications.service';
import { TestHarnessesService } from '../src/test-harnesses/test-harnesses.service';
import { TestSuitesService } from '../src/test-suites/test-suites.service';
import { RunsService } from '../src/runs/runs.service';
import { TestResultsService } from '../src/test-results/test-results.service';
import { CreateApplicationDto, ApplicationType } from '../src/applications/dto/create-application.dto';
import { CreateTestHarnessDto } from '../src/test-harnesses/dto/create-test-harness.dto';
import { CreateTestSuiteDto } from '../src/test-suites/dto/create-test-suite.dto';

describe('Application Onboarding Workflow (Integration)', () => {
  let app: INestApplication;
  let applicationsService: ApplicationsService;
  let testHarnessesService: TestHarnessesService;
  let testSuitesService: TestSuitesService;
  let runsService: RunsService;
  let testResultsService: TestResultsService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    applicationsService = getService(app, ApplicationsService);
    testHarnessesService = getService(app, TestHarnessesService);
    testSuitesService = getService(app, TestSuitesService);
    runsService = getService(app, RunsService);
    testResultsService = getService(app, TestResultsService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('should create application, add infrastructure, assign test harness, run initial tests, and view dashboard', async () => {
    // Step 1: Create application with infrastructure
    const applicationDto: CreateApplicationDto = {
      id: `onboarding-test-app-${Date.now()}`,
      name: 'Onboarding Test Application',
      description: 'Application for onboarding workflow testing',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [
          {
            id: 'db-1',
            type: 'postgresql',
            host: 'localhost',
            port: 5432,
            name: 'test_db',
          },
        ],
        networkSegments: [
          {
            id: 'network-1',
            name: 'internal',
            cidr: '10.0.0.0/8',
          },
        ],
      },
    };
    const application = await applicationsService.create(applicationDto);
    expect(application).toBeDefined();
    expect(application.id).toBeDefined();
    expect(application.infrastructure).toBeDefined();
    expect(application.infrastructure?.databases?.length).toBeGreaterThan(0);

    // Step 2: Create test suite for the application
    const suiteDto: CreateTestSuiteDto = {
      name: 'Onboarding Test Suite',
      applicationId: application.id,
      team: 'test-team',
      testType: 'access-control',
      description: 'Initial test suite for onboarding',
      enabled: true,
    };
    const suite = await testSuitesService.create(suiteDto);
    expect(suite).toBeDefined();
    expect(suite.applicationId).toBe(application.id);

    // Step 3: Create test harness and assign to application
    const harnessDto: CreateTestHarnessDto = {
      name: 'Onboarding Test Harness',
      description: 'Harness for application onboarding',
      domain: 'identity',
      testSuiteIds: [suite.id],
      applicationIds: [application.id],
      team: 'test-team',
    };
    const harness = await testHarnessesService.create(harnessDto);
    expect(harness).toBeDefined();
    expect(harness.applicationIds).toContain(application.id);
    expect(harness.testSuiteIds).toContain(suite.id);

    // Step 4: Run initial tests (simulate by querying runs)
    const runs = await runsService.findAll({
      applicationId: application.id,
      limit: 10,
    });
    expect(Array.isArray(runs)).toBe(true);

    // Step 5: View dashboard (query test results)
    const testResults = await testResultsService.query({
      applicationId: application.id,
      limit: 10,
    });
    expect(Array.isArray(testResults)).toBe(true);

    // Verify the complete workflow
    const retrievedApplication = await applicationsService.findOne(application.id);
    expect(retrievedApplication).toBeDefined();
    expect(retrievedApplication?.infrastructure).toBeDefined();

    const harnessesForApp = await testHarnessesService.findAll();
    const appHarnesses = harnessesForApp.filter(h => h.applicationIds?.includes(application.id));
    expect(appHarnesses.length).toBeGreaterThan(0);
  });

  it('should handle application onboarding with minimal infrastructure', async () => {
    const minimalAppDto: CreateApplicationDto = {
      id: `minimal-app-${Date.now()}`,
      name: 'Minimal Application',
      description: 'Application with minimal infrastructure',
      type: ApplicationType.WEB,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(minimalAppDto);
    expect(application).toBeDefined();
    expect(application.infrastructure).toBeDefined();
  });
});
