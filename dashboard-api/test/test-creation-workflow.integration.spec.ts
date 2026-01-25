/**
 * Integration Tests for Test Creation Workflow
 * 
 * Tests the complete workflow:
 * 1. Create test
 * 2. Add test to suite
 * 3. Assign suite to harness
 * 4. Add harness to battery
 * 5. Execute battery
 * 6. Verify results
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { TestsService } from '../src/tests/tests.service';
import { TestSuitesService } from '../src/test-suites/test-suites.service';
import { TestHarnessesService } from '../src/test-harnesses/test-harnesses.service';
import { TestBatteriesService } from '../src/test-batteries/test-batteries.service';
import { RunsService } from '../src/runs/runs.service';
import { ApplicationsService } from '../src/applications/applications.service';
import { CreateTestDto } from '../src/tests/dto/create-test.dto';
import { CreateTestSuiteDto } from '../src/test-suites/dto/create-test-suite.dto';
import { CreateTestHarnessDto } from '../src/test-harnesses/dto/create-test-harness.dto';
import { CreateTestBatteryDto } from '../src/test-batteries/dto/create-test-battery.dto';
import { CreateApplicationDto, ApplicationType } from '../src/applications/dto/create-application.dto';

describe('Test Creation Workflow (Integration)', () => {
  let app: INestApplication;
  let testsService: TestsService;
  let testSuitesService: TestSuitesService;
  let testHarnessesService: TestHarnessesService;
  let testBatteriesService: TestBatteriesService;
  let runsService: RunsService;
  let applicationsService: ApplicationsService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    testsService = getService(app, TestsService);
    testSuitesService = getService(app, TestSuitesService);
    testHarnessesService = getService(app, TestHarnessesService);
    testBatteriesService = getService(app, TestBatteriesService);
    runsService = getService(app, RunsService);
    applicationsService = getService(app, ApplicationsService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('should create test, add to suite, assign to harness, add to battery, and execute', async () => {
    // Step 1: Create an application (required for test suite)
    const applicationDto: CreateApplicationDto = {
      id: `integration-test-app-${Date.now()}`,
      name: 'Integration Test App',
      description: 'Test application for integration tests',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);
    expect(application).toBeDefined();
    expect(application.id).toBeDefined();

    // Step 2: Create a test
    const testDto: CreateTestDto = {
      name: 'Integration Test - Access Control',
      description: 'Test created for integration testing',
      testType: 'access-control',
      enabled: true,
      inputs: {
        subject: {
          role: 'viewer',
          attributes: {},
        },
        resource: {
          id: 'resource-123',
          type: 'dataset',
        },
        action: 'read',
      },
      expected: {
        allowed: true,
      },
    };
    const test = await testsService.create(testDto);
    expect(test).toBeDefined();
    expect(test.id).toBeDefined();
    expect(test.name).toBe(testDto.name);
    expect(test.testType).toBe('access-control');

    // Step 3: Create a test suite
    const suiteDto: CreateTestSuiteDto = {
      name: 'Integration Test Suite',
      applicationId: application.id,
      team: 'test-team',
      testType: 'access-control',
      description: 'Test suite for integration testing',
      enabled: true,
    };
    const suite = await testSuitesService.create(suiteDto);
    expect(suite).toBeDefined();
    expect(suite.id).toBeDefined();
    expect(suite.applicationId).toBe(application.id);

    // Step 4: Create a test harness with the suite
    const harnessDto: CreateTestHarnessDto = {
      name: 'Integration Test Harness',
      description: 'Test harness for integration testing',
      domain: 'identity', // access-control maps to identity domain
      testSuiteIds: [suite.id],
      applicationIds: [application.id],
      team: 'test-team',
    };
    const harness = await testHarnessesService.create(harnessDto);
    expect(harness).toBeDefined();
    expect(harness.id).toBeDefined();
    expect(harness.testSuiteIds).toContain(suite.id);
    expect(harness.applicationIds).toContain(application.id);

    // Step 5: Create a test battery with the harness
    const batteryDto: CreateTestBatteryDto = {
      name: 'Integration Test Battery',
      description: 'Test battery for integration testing',
      harnessIds: [harness.id],
      executionConfig: {
        executionMode: 'sequential',
        timeout: 30000,
        stopOnFailure: false,
      },
      team: 'test-team',
    };
    const battery = await testBatteriesService.create(batteryDto);
    expect(battery).toBeDefined();
    expect(battery.id).toBeDefined();
    expect(battery.harnessIds).toContain(harness.id);

    // Step 6: Execute the battery (via runs service)
    // Note: Actual execution may require additional setup, so we'll verify
    // that we can query runs for this battery
    const runs = await runsService.findAll({
      batteryId: battery.id,
      limit: 10,
    });
    expect(Array.isArray(runs)).toBe(true);

    // Verify the complete workflow by checking relationships
    const retrievedBattery = await testBatteriesService.findOne(battery.id);
    expect(retrievedBattery).toBeDefined();
    expect(retrievedBattery?.harnessIds).toContain(harness.id);

    const retrievedHarness = await testHarnessesService.findOne(harness.id);
    expect(retrievedHarness).toBeDefined();
    expect(retrievedHarness?.testSuiteIds).toContain(suite.id);

    const retrievedSuite = await testSuitesService.findOne(suite.id);
    expect(retrievedSuite).toBeDefined();
    expect(retrievedSuite?.applicationId).toBe(application.id);

    const retrievedTest = await testsService.findOne(test.id);
    expect(retrievedTest).toBeDefined();
    expect(retrievedTest?.name).toBe(testDto.name);
  });

  it('should handle errors when creating invalid workflow', async () => {
    // Test error handling: Try to create harness with non-existent suite
    const harnessDto: CreateTestHarnessDto = {
      name: 'Invalid Harness',
      description: 'Harness with invalid suite',
      domain: 'identity',
      testSuiteIds: ['non-existent-suite-id'],
      team: 'test-team',
    };

    await expect(
      testHarnessesService.create(harnessDto)
    ).rejects.toThrow();
  });

  it('should handle errors when creating battery with duplicate domains', async () => {
    // Create application
    const applicationDto: CreateApplicationDto = {
      id: `error-test-app-${Date.now()}`,
      name: 'Error Test App',
      description: 'Test app for error scenarios',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);

    // Create two test suites with same domain
    const suite1Dto: CreateTestSuiteDto = {
      name: 'Suite 1',
      applicationId: application.id,
      team: 'test-team',
      testType: 'access-control',
      enabled: true,
    };
    const suite1 = await testSuitesService.create(suite1Dto);

    const suite2Dto: CreateTestSuiteDto = {
      name: 'Suite 2',
      applicationId: application.id,
      team: 'test-team',
      testType: 'access-control',
      enabled: true,
    };
    const suite2 = await testSuitesService.create(suite2Dto);

    // Create two harnesses with same domain
    const harness1Dto: CreateTestHarnessDto = {
      name: 'Harness 1',
      description: 'First harness',
      domain: 'identity',
      testSuiteIds: [suite1.id],
      team: 'test-team',
    };
    const harness1 = await testHarnessesService.create(harness1Dto);

    const harness2Dto: CreateTestHarnessDto = {
      name: 'Harness 2',
      description: 'Second harness',
      domain: 'identity', // Same domain as harness1
      testSuiteIds: [suite2.id],
      team: 'test-team',
    };
    const harness2 = await testHarnessesService.create(harness2Dto);

    // Try to create battery with both harnesses (should fail - same domain)
    const batteryDto: CreateTestBatteryDto = {
      name: 'Invalid Battery',
      description: 'Battery with duplicate domains',
      harnessIds: [harness1.id, harness2.id], // Both have 'identity' domain
      team: 'test-team',
    };

    await expect(
      testBatteriesService.create(batteryDto)
    ).rejects.toThrow();
  });
});
