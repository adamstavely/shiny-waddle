/**
 * E2E Tests for Complex User Workflows
 * 
 * Phase 4.2: Complex User Workflows E2E Tests
 * 
 * Workflows:
 * 1. Create application → Configure infrastructure → Run tests → View results
 * 2. Create test suite → Add tests → Configure → Execute → View findings
 * 3. Create policy → Validate → Deploy → Monitor → Update
 * 4. View dashboard → Filter data → Export reports → Schedule reports
 * 5. Manage users → Assign roles → Grant permissions → Audit access
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';

describe('Complex User Workflows (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

    await app.close();
  });

  describe('Workflow 1: Application Creation → Infrastructure → Run Tests → View Results', () => {
    let applicationId: string;

    it('should create application with infrastructure configuration', async () => {
      const createAppDto = {
        id: `e2e-app-${Date.now()}`,
        name: 'E2E Test Application',
        description: 'Application for E2E workflow testing',
        type: 'api',
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
          apiSecurity: {
            endpoints: [
              {
                path: '/api/v1/users',
                method: 'GET',
                requiresAuth: true,
              },
            ],
          },
        },
      };

      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send(createAppDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('infrastructure');
      expect(response.body.infrastructure).toHaveProperty('databases');
      expect(response.body.infrastructure.databases.length).toBeGreaterThan(0);
      applicationId = response.body.id;
    });

    it('should update application infrastructure configuration', async () => {
      const updateInfrastructureDto = {
        infrastructure: {
          databases: [
            {
              id: 'db-1',
              type: 'postgresql',
              host: 'localhost',
              port: 5432,
              name: 'test_db',
            },
            {
              id: 'db-2',
              type: 'mysql',
              host: 'localhost',
              port: 3306,
              name: 'analytics_db',
            },
          ],
          networkSegments: [
            {
              id: 'network-1',
              name: 'internal',
              cidr: '10.0.0.0/8',
            },
            {
              id: 'network-2',
              name: 'dmz',
              cidr: '192.168.1.0/24',
            },
          ],
        },
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/applications/${applicationId}`)
        .send(updateInfrastructureDto)
        .expect(200);

      expect(response.body.infrastructure.databases.length).toBe(2);
      expect(response.body.infrastructure.networkSegments.length).toBe(2);
    });

    it('should run tests for application', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/applications/${applicationId}/run-tests`)
        .query({
          buildId: 'build-123',
          commitSha: 'abc123def',
          branch: 'main',
        })
        .expect(200);

      expect(response.body).toHaveProperty('status');
      expect(response.body).toHaveProperty('totalTests');
      expect(['passed', 'failed', 'partial']).toContain(response.body.status);
    });

    it('should view test results for application', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/test-results/application/${applicationId}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should get test configurations for application', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/applications/${applicationId}/test-configurations`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Workflow 2: Create Test Suite → Add Tests → Configure → Execute → View Findings', () => {
    let applicationId: string;
    let testSuiteId: string;
    let testId: string;

    beforeEach(async () => {
      // Create application for test suite
      const createAppDto = {
        id: `e2e-suite-app-${Date.now()}`,
        name: 'Test Suite Application',
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

    it('should create test suite', async () => {
      const createSuiteDto = {
        name: 'E2E Test Suite',
        applicationId: applicationId,
        team: 'test-team',
        testType: 'access-control',
        description: 'Test suite for E2E workflow testing',
        enabled: true,
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/test-suites')
        .send(createSuiteDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createSuiteDto.name);
      expect(response.body).toHaveProperty('testType', 'access-control');
      testSuiteId = response.body.id;
    });

    it('should create a test and add to suite', async () => {
      const createTestDto = {
        name: 'E2E Access Control Test',
        description: 'Test created for E2E workflow',
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

      const testResponse = await request(app.getHttpServer())
        .post('/api/tests')
        .send(createTestDto)
        .expect(201);

      expect(testResponse.body).toHaveProperty('id');
      testId = testResponse.body.id;

      // Add test to suite (if endpoint exists)
      // Note: This may require updating the suite with testIds array
      const updateSuiteDto = {
        testIds: [testId],
      };

      const updateResponse = await request(app.getHttpServer())
        .put(`/api/v1/test-suites/${testSuiteId}`)
        .send(updateSuiteDto)
        .expect(200);

      expect(updateResponse.body).toHaveProperty('testIds');
      expect(Array.isArray(updateResponse.body.testIds)).toBe(true);
    });

    it('should configure test suite', async () => {
      const updateSuiteDto = {
        enabled: true,
        description: 'Updated test suite configuration',
      };

      const response = await request(app.getHttpServer())
        .put(`/api/v1/test-suites/${testSuiteId}`)
        .send(updateSuiteDto)
        .expect(200);

      expect(response.body.enabled).toBe(true);
      expect(response.body.description).toBe(updateSuiteDto.description);
    });

    it('should execute test suite', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-suites/${testSuiteId}/run`)
        .expect(200);

      expect(response.body).toHaveProperty('suiteId', testSuiteId);
      expect(response.body).toHaveProperty('status');
      expect(response.body).toHaveProperty('totalTests');
      expect(response.body).toHaveProperty('results');
      expect(Array.isArray(response.body.results)).toBe(true);
    });

    it('should view test suite results', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/test-suites/${testSuiteId}/results`)
        .expect(200);

      expect(response.body).toHaveProperty('suiteId', testSuiteId);
      expect(response.body).toHaveProperty('results');
      expect(Array.isArray(response.body.results)).toBe(true);
    });
  });

  describe('Workflow 3: Create Policy → Validate → Deploy → Monitor → Update', () => {
    let policyId: string;

    it('should create a policy', async () => {
      const createPolicyDto = {
        name: 'E2E Test Policy',
        description: 'Policy for E2E workflow testing',
        type: 'access-control',
        status: 'draft',
        effect: 'allow',
        conditions: [
          {
            field: 'user.role',
            operator: 'equals',
            value: 'viewer',
          },
        ],
        resources: ['dataset:*'],
        actions: ['read'],
      };

      const response = await request(app.getHttpServer())
        .post('/api/policies')
        .send(createPolicyDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createPolicyDto.name);
      expect(response.body).toHaveProperty('type', 'access-control');
      policyId = response.body.id;
    });

    it('should validate policy for conflicts', async () => {
      const validateDto = {
        policies: [
          {
            id: policyId,
            name: 'E2E Test Policy',
            effect: 'allow',
            conditions: [],
          },
        ],
      };

      const response = await request(app.getHttpServer())
        .post('/api/policy-validation/detect-conflicts')
        .send(validateDto)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should analyze policy coverage', async () => {
      const analyzeDto = {
        resources: [
          {
            id: 'resource-123',
            type: 'dataset',
            attributes: {},
          },
        ],
        policies: [
          {
            id: policyId,
            name: 'E2E Test Policy',
            effect: 'allow',
            conditions: [],
          },
        ],
      };

      const response = await request(app.getHttpServer())
        .post('/api/policy-validation/analyze-coverage')
        .send(analyzeDto)
        .expect(200);

      expect(response.body).toHaveProperty('totalResources');
      expect(response.body).toHaveProperty('resourcesWithPolicies');
    });

    it('should test policy performance', async () => {
      const performanceDto = {
        policy: {
          id: policyId,
          name: 'E2E Test Policy',
          effect: 'allow',
          conditions: [],
        },
      };

      const response = await request(app.getHttpServer())
        .post('/api/policy-validation/test-performance')
        .send(performanceDto)
        .expect(200);

      expect(response.body).toHaveProperty('executionTime');
    });

    it('should update policy status to active (deploy)', async () => {
      const updateDto = {
        status: 'active',
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/policies/${policyId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('status', 'active');
    });

    it('should monitor policy (get policy details)', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/policies/${policyId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', policyId);
      expect(response.body).toHaveProperty('status');
    });

    it('should update policy', async () => {
      const updateDto = {
        description: 'Updated policy description',
        conditions: [
          {
            field: 'user.role',
            operator: 'equals',
            value: 'editor',
          },
        ],
      };

      const response = await request(app.getHttpServer())
        .patch(`/api/policies/${policyId}`)
        .send(updateDto)
        .expect(200);

      expect(response.body).toHaveProperty('description', updateDto.description);
    });
  });

  describe('Workflow 4: View Dashboard → Filter Data → Export Reports → Schedule Reports', () => {
    let applicationId: string;

    beforeEach(async () => {
      // Create application for dashboard testing
      const createAppDto = {
        id: `e2e-dashboard-app-${Date.now()}`,
        name: 'Dashboard Test Application',
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

    it('should view dashboard - get all applications', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter applications by team', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications')
        .query({ team: 'test-team' })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter test results by application', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({ applicationId: applicationId })
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

    it('should create a scheduled report', async () => {
      const createReportDto = {
        name: 'E2E Scheduled Report',
        description: 'Report for E2E workflow testing',
        reportType: 'compliance',
        schedule: {
          frequency: 'weekly',
          dayOfWeek: 'monday',
          time: '09:00',
        },
        recipients: ['test@example.com'],
        filters: {
          applicationIds: [applicationId],
        },
      };

      const response = await request(app.getHttpServer())
        .post('/api/scheduled-reports')
        .send(createReportDto)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name', createReportDto.name);
      expect(response.body).toHaveProperty('schedule');
    });

    it('should list scheduled reports', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/scheduled-reports')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Workflow 5: Manage Users → Assign Roles → Grant Permissions → Audit Access', () => {
    let userId: string;

    it('should register a new user', async () => {
      const registerDto = {
        email: `e2e-user-${Date.now()}@example.com`,
        password: 'TestPassword123!',
        name: 'E2E Test User',
        roles: ['viewer'],
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send(registerDto)
        .expect(201);

      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('id');
      expect(response.body.user).toHaveProperty('email', registerDto.email);
      userId = response.body.user.id;
    });

    it('should get all users', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/users')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should get user by ID', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/users/${userId}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', userId);
    });

    it('should filter users by role', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/users/by-role/viewer')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter users by application', async () => {
      // First create an application
      const createAppDto = {
        id: `e2e-user-app-${Date.now()}`,
        name: 'User Management App',
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

      const appId = appResponse.body.id;

      // Query users by application
      const response = await request(app.getHttpServer())
        .get(`/api/v1/users/by-application/${appId}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should filter users by team', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/users/by-team/test-team')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should query users by context (applicationIds and teamNames)', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/users/by-context/query')
        .query({
          teamNames: 'test-team',
        })
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should verify user roles are assigned correctly', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/users/${userId}`)
        .expect(200);

      expect(response.body).toHaveProperty('roles');
      expect(Array.isArray(response.body.roles)).toBe(true);
      expect(response.body.roles).toContain('viewer');
    });

    it('should access audit logs (if endpoint exists)', async () => {
      // Note: Audit log endpoints may require admin permissions
      // This test verifies the endpoint exists and returns data
      const response = await request(app.getHttpServer())
        .get('/api/security/audit-logs')
        .query({
          limit: 10,
        })
        .expect((res) => {
          // Accept 200 (if accessible) or 403/401 (if requires auth)
          expect([200, 401, 403]).toContain(res.status);
        });

      if (response.status === 200) {
        expect(Array.isArray(response.body)).toBe(true);
      }
    });
  });

  describe('Workflow Integration: Complete End-to-End Scenario', () => {
    it('should complete full workflow: app → suite → harness → battery → execute → results', async () => {
      // Step 1: Create application
      const createAppDto = {
        id: `e2e-full-workflow-app-${Date.now()}`,
        name: 'Full Workflow Application',
        type: 'api',
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
          networkSegments: [],
        },
      };

      const appResponse = await request(app.getHttpServer())
        .post('/api/applications')
        .send(createAppDto)
        .expect(201);

      const applicationId = appResponse.body.id;

      // Step 2: Create test suite
      const createSuiteDto = {
        name: 'Full Workflow Test Suite',
        applicationId: applicationId,
        team: 'test-team',
        testType: 'access-control',
        enabled: true,
      };

      const suiteResponse = await request(app.getHttpServer())
        .post('/api/v1/test-suites')
        .send(createSuiteDto)
        .expect(201);

      const testSuiteId = suiteResponse.body.id;

      // Step 3: Create test harness
      const createHarnessDto = {
        name: 'Full Workflow Test Harness',
        description: 'Harness for full workflow testing',
        domain: 'identity',
        testSuiteIds: [testSuiteId],
        applicationIds: [applicationId],
        team: 'test-team',
      };

      const harnessResponse = await request(app.getHttpServer())
        .post('/api/v1/test-harnesses')
        .send(createHarnessDto)
        .expect(201);

      const harnessId = harnessResponse.body.id;

      // Step 4: Create test battery
      const createBatteryDto = {
        name: 'Full Workflow Test Battery',
        description: 'Battery for full workflow testing',
        harnessIds: [harnessId],
        executionConfig: {
          executionMode: 'parallel',
          timeout: 3600000,
          stopOnFailure: false,
        },
        team: 'test-team',
      };

      const batteryResponse = await request(app.getHttpServer())
        .post('/api/test-batteries')
        .send(createBatteryDto)
        .expect(201);

      const batteryId = batteryResponse.body.id;

      // Step 5: Execute battery (via application run-tests endpoint)
      // Note: Batteries are executed through applications, not directly
      const executeResponse = await request(app.getHttpServer())
        .post(`/api/applications/${applicationId}/run-tests`)
        .query({
          buildId: 'build-123',
          commitSha: 'abc123def',
          branch: 'main',
        })
        .expect(200);

      expect(executeResponse.body).toHaveProperty('status');

      // Step 6: View results
      const resultsResponse = await request(app.getHttpServer())
        .get(`/api/test-results/application/${applicationId}`)
        .expect(200);

      expect(Array.isArray(resultsResponse.body)).toBe(true);

      // Verify all entities were created
      expect(applicationId).toBeDefined();
      expect(testSuiteId).toBeDefined();
      expect(harnessId).toBeDefined();
      expect(batteryId).toBeDefined();
    });
  });
});
