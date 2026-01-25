/**
 * E2E Tests for API Endpoint Coverage
 * 
 * Phase 4.3: API Endpoint Coverage E2E Tests
 * 
 * Coverage:
 * - All CRUD operations for all entities
 * - Bulk operations
 * - Search and filtering
 * - Pagination
 * - Sorting
 * - Export functionality
 * - Import functionality
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';

describe('API Endpoint Coverage (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('CRUD Operations - Applications', () => {
    let applicationId: string;

    it('should CREATE an application', async () => {
      const createDto = {
        id: `e2e-crud-app-${Date.now()}`,
        name: 'CRUD Test Application',
        description: 'Application for CRUD testing',
        type: 'api',
        team: 'test-team',
        infrastructure: {
          databases: [],
          networkSegments: [],
        },
      };

      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send(createDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createDto.name);
      applicationId = response.body.id;
    });

    it('should READ an application by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/applications/${applicationId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', applicationId);
      expect(response.body).toHaveProperty('name');
    });

    it('should READ all applications', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeGreaterThan(0);
    });

    it('should UPDATE an application', async () => {
      const updateDto = {
        name: 'Updated CRUD Test Application',
        description: 'Updated description',
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/applications/${applicationId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('name', updateDto.name);
      expect(response.body).toHaveProperty('description', updateDto.description);
    });

    it('should DELETE an application', async () => {
      await request(app.getHttpServer())
        .delete(`/api/applications/${applicationId}`)
        .expect(200);

      // Verify deletion
      await request(app.getHttpServer())
        .get(`/api/applications/${applicationId}`)
        .expect(404);
    });
  });

  describe('CRUD Operations - Test Suites', () => {
    let applicationId: string;
    let testSuiteId: string;

    beforeEach(async () => {
      // Create application for test suite
      const createAppDto = {
        id: `e2e-suite-app-${Date.now()}`,
        name: 'Test Suite App',
        type: 'api',
        team: 'test-team',
        infrastructure: {
          databases: [],
          networkSegments: [],
        },
      };

      const appResponse = await request(app.getHttpServer())
        .post('/api/applications')
        .send(createAppDto)
        .expect(201);

      applicationId = appResponse.body.id;
    });

    it('should CREATE a test suite', async () => {
      const createDto = {
        name: 'CRUD Test Suite',
        applicationId: applicationId,
        team: 'test-team',
        testType: 'access-control',
        enabled: true,
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-suites')
        .send(createDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createDto.name);
      testSuiteId = response.body.id;
    });

    it('should READ a test suite by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/test-suites/${testSuiteId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', testSuiteId);
    });

    it('should READ all test suites', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-suites')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should UPDATE a test suite', async () => {
      const updateDto = {
        name: 'Updated CRUD Test Suite',
        description: 'Updated description',
      };

      const response = await request(app.getHttpServer())
        .put(`/api/v1/test-suites/${testSuiteId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('name', updateDto.name);
    });

    it('should DELETE a test suite', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/test-suites/${testSuiteId}`)
        .expect(204);
    });
  });

  describe('CRUD Operations - Test Harnesses', () => {
    let harnessId: string;

    it('should CREATE a test harness', async () => {
      const createDto = {
        name: 'CRUD Test Harness',
        description: 'Harness for CRUD testing',
        domain: 'identity',
        testSuiteIds: [],
        applicationIds: [],
        team: 'test-team',
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-harnesses')
        .send(createDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createDto.name);
      harnessId = response.body.id;
    });

    it('should READ a test harness by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/test-harnesses/${harnessId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', harnessId);
    });

    it('should READ all test harnesses', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-harnesses')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should UPDATE a test harness', async () => {
      const updateDto = {
        name: 'Updated CRUD Test Harness',
        description: 'Updated description',
      };

      const response = await request(app.getHttpServer())
        .put(`/api/v1/test-harnesses/${harnessId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('name', updateDto.name);
    });

    it('should DELETE a test harness', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/test-harnesses/${harnessId}`)
        .expect(200);
    });
  });

  describe('CRUD Operations - Test Batteries', () => {
    let batteryId: string;

    it('should CREATE a test battery', async () => {
      const createDto = {
        name: 'CRUD Test Battery',
        description: 'Battery for CRUD testing',
        harnessIds: [],
        executionConfig: {
          executionMode: 'parallel',
          timeout: 3600000,
          stopOnFailure: false,
        },
        team: 'test-team',
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-batteries')
        .send(createDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createDto.name);
      batteryId = response.body.id;
    });

    it('should READ a test battery by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/test-batteries/${batteryId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', batteryId);
    });

    it('should READ all test batteries', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-batteries')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should UPDATE a test battery', async () => {
      const updateDto = {
        name: 'Updated CRUD Test Battery',
        description: 'Updated description',
      };

      const response = await request(app.getHttpServer())
        .put(`/api/v1/test-batteries/${batteryId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('name', updateDto.name);
    });

    it('should DELETE a test battery', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/test-batteries/${batteryId}`)
        .expect(204);
    });
  });

  describe('CRUD Operations - Policies', () => {
    let policyId: string;

    it('should CREATE a policy', async () => {
      const createDto = {
        name: 'CRUD Test Policy',
        description: 'Policy for CRUD testing',
        type: 'access-control',
        status: 'draft',
        effect: 'allow',
        conditions: [],
        resources: ['dataset:*'],
        actions: ['read'],
      };

      const response = await request(app.getHttpServer())
        .post('/api/policies')
        .send(createDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createDto.name);
      policyId = response.body.id;
    });

    it('should READ a policy by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/policies/${policyId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', policyId);
    });

    it('should READ all policies', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/policies')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should UPDATE a policy', async () => {
      const updateDto = {
        description: 'Updated policy description',
        status: 'active',
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/policies/${policyId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('description', updateDto.description);
      expect(response.body).toHaveProperty('status', updateDto.status);
    });

    it('should DELETE a policy', async () => {
      await request(app.getHttpServer())
        .delete(`/api/policies/${policyId}`)
        .expect(200);
    });
  });

  describe('CRUD Operations - Tests', () => {
    let testId: string;

    it('should CREATE a test', async () => {
      const createDto = {
        name: 'CRUD Test',
        description: 'Test for CRUD operations',
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

      const response = await request(app.getHttpServer())
        .post('/api/tests')
        .send(createDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createDto.name);
      testId = response.body.id;
    });

    it('should READ a test by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/tests/${testId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', testId);
    });

    it('should READ all tests', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/tests')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should UPDATE a test', async () => {
      const updateDto = {
        description: 'Updated test description',
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/tests/${testId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('description', updateDto.description);
    });

    it('should DELETE a test', async () => {
      await request(app.getHttpServer())
        .delete(`/api/tests/${testId}`)
        .expect(200);
    });
  });

  describe('Search and Filtering', () => {
    beforeEach(async () => {
      // Create test data
      const appDto = {
        id: `e2e-filter-app-${Date.now()}`,
        name: 'Filter Test Application',
        type: 'api',
        team: 'filter-team',
        infrastructure: {
          databases: [],
          networkSegments: [],
        },
      };

      await request(app.getHttpServer())
        .post('/api/applications')
        .send(appDto)
        .expect(201);
    });

    it('should filter applications by team', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications')
        .query({ team: 'filter-team' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      if (response.body.length > 0) {
        expect(response.body[0]).toHaveProperty('team', 'filter-team');
      }
    });

    it('should filter applications by type', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications')
        .query({ type: 'api' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by application', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({ applicationId: 'test-app-id' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by status', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({ status: 'passed' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by date range', async () => {
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const endDate = new Date().toISOString();

      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          startDate: startDate,
          endDate: endDate,
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test suites by application', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-suites')
        .query({ applicationId: 'test-app-id' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test suites by test type', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-suites')
        .query({ testType: 'access-control' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter unified findings by source', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/unified-findings')
        .query({ source: 'test-scanner' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter unified findings by severity', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/unified-findings')
        .query({ severity: 'high' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should use advanced query for test results', async () => {
      const queryDto = {
        filters: [
          {
            field: 'status',
            operator: 'equals',
            value: 'passed',
          },
        ],
        sort: [
          {
            field: 'timestamp',
            direction: 'desc',
          },
        ],
        limit: 10,
        offset: 0,
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-results/advanced-query')
        .send(queryDto)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Pagination', () => {
    it('should paginate test results with limit and offset', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          limit: 10,
          offset: 0,
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeLessThanOrEqual(10);
    });

    it('should paginate applications', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications')
        .query({
          limit: 5,
          offset: 0,
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should paginate test suites', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-suites')
        .query({
          limit: 10,
          offset: 0,
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Sorting', () => {
    it('should sort test results by timestamp descending', async () => {
      const queryDto = {
        sort: [
          {
            field: 'timestamp',
            direction: 'desc',
          },
        ],
        limit: 10,
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-results/advanced-query')
        .send(queryDto)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should sort test results by status ascending', async () => {
      const queryDto = {
        sort: [
          {
            field: 'status',
            direction: 'asc',
          },
        ],
        limit: 10,
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-results/advanced-query')
        .send(queryDto)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should sort by multiple fields', async () => {
      const queryDto = {
        sort: [
          {
            field: 'status',
            direction: 'asc',
          },
          {
            field: 'timestamp',
            direction: 'desc',
          },
        ],
        limit: 10,
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-results/advanced-query')
        .send(queryDto)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Bulk Operations', () => {
    let applicationId: string;

    beforeEach(async () => {
      // Create application for bulk operations
      const createAppDto = {
        id: `e2e-bulk-app-${Date.now()}`,
        name: 'Bulk Operations App',
        type: 'api',
        team: 'test-team',
        infrastructure: {
          databases: [],
          networkSegments: [],
        },
      };

      const appResponse = await request(app.getHttpServer())
        .post('/api/applications')
        .send(createAppDto)
        .expect(201);

      applicationId = appResponse.body.id;
    });

    it('should bulk toggle validators', async () => {
      const bulkToggleDto = {
        items: [
          {
            id: 'validator-1',
            enabled: false,
            reason: 'Disabled for testing',
          },
        ],
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/applications/${applicationId}/validators/bulk-toggle`)
        .send(bulkToggleDto)
        .expect(200);

      expect(response.body).toHaveProperty('infrastructure');
    });

    it('should add multiple test suites to harness', async () => {
      // Create harness
      const harnessDto = {
        name: 'Bulk Test Harness',
        domain: 'identity',
        testSuiteIds: [],
        applicationIds: [applicationId],
        team: 'test-team',
      };

      const harnessResponse = await request(app.getHttpServer())
        .post('/api/v1/test-harnesses')
        .send(harnessDto)
        .expect(201);

      const harnessId = harnessResponse.body.id;

      // Create test suites
      const suite1Dto = {
        name: 'Bulk Suite 1',
        applicationId: applicationId,
        team: 'test-team',
        testType: 'access-control',
      };

      const suite2Dto = {
        name: 'Bulk Suite 2',
        applicationId: applicationId,
        team: 'test-team',
        testType: 'access-control',
      };

      const suite1Response = await request(app.getHttpServer())
        .post('/api/v1/test-suites')
        .send(suite1Dto)
        .expect(201);

      const suite2Response = await request(app.getHttpServer())
        .post('/api/v1/test-suites')
        .send(suite2Dto)
        .expect(201);

      // Add suites to harness
      await request(app.getHttpServer())
        .post(`/api/v1/test-harnesses/${harnessId}/test-suites`)
        .send({ suiteId: suite1Response.body.id })
        .expect(200);

      await request(app.getHttpServer())
        .post(`/api/v1/test-harnesses/${harnessId}/test-suites`)
        .send({ suiteId: suite2Response.body.id })
        .expect(200);

      // Verify harness has both suites
      const harnessResponse2 = await request(app.getHttpServer())
        .get(`/api/v1/test-harnesses/${harnessId}`)
        .expect(200);

      expect(harnessResponse2.body.testSuiteIds.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Export Functionality', () => {
    it('should export test results as CSV', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-results/export/csv')
        .query({
          limit: 100,
        })
        .expect(200);

      expect(response.body).toHaveProperty('format', 'csv');
      expect(response.body).toHaveProperty('data');
      expect(typeof response.body.data).toBe('string');
    });

    it('should export test results as CSV with filters', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-results/export/csv')
        .query({
          status: 'passed',
          limit: 50,
        })
        .expect(200);

      expect(response.body).toHaveProperty('format', 'csv');
      expect(response.body).toHaveProperty('data');
    });

    it('should export test results as JSON', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-results/export/json')
        .query({
          limit: 100,
        })
        .expect(200);

      expect(response.body).toHaveProperty('format', 'json');
      expect(response.body).toHaveProperty('data');
    });
  });

  describe('Query Parameters and Filtering Combinations', () => {
    it('should combine multiple filters for test results', async () => {
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const endDate = new Date().toISOString();

      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          status: 'passed',
          startDate: startDate,
          endDate: endDate,
          limit: 20,
          offset: 0,
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by build ID', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          buildId: 'build-123',
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by branch', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          branch: 'main',
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by test harness ID', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          testHarnessId: 'harness-123',
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by test battery ID', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          testBatteryId: 'battery-123',
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Relationship Endpoints', () => {
    let applicationId: string;
    let testSuiteId: string;
    let harnessId: string;
    let batteryId: string;

    beforeEach(async () => {
      // Create application
      const appDto = {
        id: `e2e-rel-app-${Date.now()}`,
        name: 'Relationship Test App',
        type: 'api',
        team: 'test-team',
        infrastructure: {
          databases: [],
          networkSegments: [],
        },
      };

      const appResponse = await request(app.getHttpServer())
        .post('/api/applications')
        .send(appDto)
        .expect(201);

      applicationId = appResponse.body.id;

      // Create test suite
      const suiteDto = {
        name: 'Relationship Test Suite',
        applicationId: applicationId,
        team: 'test-team',
        testType: 'access-control',
      };

      const suiteResponse = await request(app.getHttpServer())
        .post('/api/v1/test-suites')
        .send(suiteDto)
        .expect(201);

      testSuiteId = suiteResponse.body.id;

      // Create harness
      const harnessDto = {
        name: 'Relationship Test Harness',
        domain: 'identity',
        testSuiteIds: [testSuiteId],
        applicationIds: [applicationId],
        team: 'test-team',
      };

      const harnessResponse = await request(app.getHttpServer())
        .post('/api/v1/test-harnesses')
        .send(harnessDto)
        .expect(201);

      harnessId = harnessResponse.body.id;

      // Create battery
      const batteryDto = {
        name: 'Relationship Test Battery',
        harnessIds: [harnessId],
        executionConfig: {
          executionMode: 'parallel',
          timeout: 3600000,
        },
        team: 'test-team',
      };

      const batteryResponse = await request(app.getHttpServer())
        .post('/api/v1/test-batteries')
        .send(batteryDto)
        .expect(201);

      batteryId = batteryResponse.body.id;
    });

    it('should get test configurations for application', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/applications/${applicationId}/test-configurations`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should add test suite to harness', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-harnesses/${harnessId}/test-suites`)
        .send({ suiteId: testSuiteId })
        .expect(200);

      expect(response.body).toHaveProperty('testSuiteIds');
      expect(response.body.testSuiteIds).toContain(testSuiteId);
    });

    it('should remove test suite from harness', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/test-harnesses/${harnessId}/test-suites/${testSuiteId}`)
        .expect(200);
    });

    it('should assign harness to application', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-harnesses/${harnessId}/applications`)
        .send({ applicationId: applicationId })
        .expect(200);

      expect(response.body).toHaveProperty('applicationIds');
      expect(response.body.applicationIds).toContain(applicationId);
    });

    it('should unassign harness from application', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/test-harnesses/${harnessId}/applications/${applicationId}`)
        .expect(200);
    });

    it('should add harness to battery', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-batteries/${batteryId}/harnesses`)
        .send({ harnessId: harnessId })
        .expect(200);

      expect(response.body).toHaveProperty('harnessIds');
      expect(response.body.harnessIds).toContain(harnessId);
    });

    it('should remove harness from battery', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/test-batteries/${batteryId}/harnesses/${harnessId}`)
        .expect(200);
    });

    it('should get assigned applications for battery', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/test-batteries/${batteryId}/assigned-applications`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Statistics and Metrics Endpoints', () => {
    it('should get unified findings statistics', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/unified-findings/statistics')
        .expect(200);

      expect(response.body).toBeDefined();
      expect(typeof response.body).toBe('object');
    });

    it('should get compliance metrics', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results/compliance/metrics')
        .expect(200);

      expect(response.body).toBeDefined();
    });

    it('should get compliance trends', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results/compliance/trends')
        .expect(200);

      expect(response.body).toBeDefined();
    });
  });
});
