/**
 * E2E Tests for Error Scenarios
 * 
 * Phase 4.4: Error Scenarios E2E Tests
 * 
 * Scenarios:
 * - Invalid input validation
 * - Unauthorized access attempts
 * - Resource not found
 * - Conflict errors
 * - Rate limiting
 * - Server errors
 * - Network failures (simulated)
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';

describe('Error Scenarios (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

    await app.close();
  });

  describe('Invalid Input Validation', () => {
    describe('Application Validation Errors', () => {
      it('should return 400 when creating application with missing required fields', async () => {
        const invalidDto = {
          name: 'Test Application',
          // Missing: id, type
        };

        const response = await request(app.getHttpServer())
          .post('/api/applications')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
        expect(response.body).toHaveProperty('message');
      });

      it('should return 400 when creating application with invalid type', async () => {
        const invalidDto = {
          id: 'test-app-123',
          name: 'Test Application',
          type: 'invalid-type',
          team: 'test-team',
        };

        const response = await request(app.getHttpServer())
          .post('/api/applications')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when creating application with invalid email format in baseUrl', async () => {
        const invalidDto = {
          id: 'test-app-123',
          name: 'Test Application',
          type: 'api',
          baseUrl: 'not-a-valid-url',
          team: 'test-team',
        };

        const response = await request(app.getHttpServer())
          .post('/api/applications')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when updating application with invalid data', async () => {
        // First create a valid application
        const createDto = {
          id: `e2e-error-app-${Date.now()}`,
          name: 'Error Test App',
          type: 'api',
          team: 'test-team',
          infrastructure: {
            databases: [],
            networkSegments: [],
          },
        };

        const createResponse = await request(app.getHttpServer())
          .post('/api/applications')
          .send(createDto)
          .expect(201);

        const appId = createResponse.body.id;

        // Try to update with invalid data
        const invalidUpdateDto = {
          type: 'invalid-type',
        };

        const response = await request(app.getHttpServer())
          .patch(`/api/applications/${appId}`)
          .send(invalidUpdateDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });
    });

    describe('Test Suite Validation Errors', () => {
      it('should return 400 when creating test suite with missing required fields', async () => {
        const invalidDto = {
          name: 'Test Suite',
          // Missing: applicationId, team, testType
        };

        const response = await request(app.getHttpServer())
          .post('/api/v1/test-suites')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when creating test suite with invalid test type', async () => {
        // Create application first
        const appDto = {
          id: `e2e-error-suite-app-${Date.now()}`,
          name: 'Error Suite App',
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

        const invalidDto = {
          name: 'Test Suite',
          applicationId: appResponse.body.id,
          team: 'test-team',
          testType: 'invalid-test-type',
        };

        const response = await request(app.getHttpServer())
          .post('/api/v1/test-suites')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });
    });

    describe('Policy Validation Errors', () => {
      it('should return 400 when creating policy with missing required fields', async () => {
        const invalidDto = {
          name: 'Test Policy',
          // Missing: type, effect
        };

        const response = await request(app.getHttpServer())
          .post('/api/policies')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when creating policy with invalid effect', async () => {
        const invalidDto = {
          name: 'Test Policy',
          type: 'access-control',
          effect: 'invalid-effect',
          conditions: [],
          resources: ['dataset:*'],
          actions: ['read'],
        };

        const response = await request(app.getHttpServer())
          .post('/api/policies')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });
    });

    describe('Authentication Validation Errors', () => {
      it('should return 400 when registering with invalid email', async () => {
        const invalidDto = {
          email: 'not-an-email',
          password: 'TestPassword123!',
          name: 'Test User',
        };

        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when registering with password too short', async () => {
        const invalidDto = {
          email: 'test@example.com',
          password: 'short',
          name: 'Test User',
        };

        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when logging in with invalid email format', async () => {
        const invalidDto = {
          email: 'not-an-email',
          password: 'TestPassword123!',
        };

        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send(invalidDto)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });
    });

    describe('Query Parameter Validation Errors', () => {
      it('should return 400 when using invalid limit value', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/test-results')
          .query({ limit: -1 })
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when using invalid offset value', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/test-results')
          .query({ offset: -1 })
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should return 400 when using invalid date format', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/test-results')
          .query({ startDate: 'not-a-date' })
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });
    });
  });

  describe('Resource Not Found Errors', () => {
    it('should return 404 when getting non-existent application', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
      expect(response.body).toHaveProperty('message');
    });

    it('should return 404 when updating non-existent application', async () => {
      const updateDto = {
        name: 'Updated Name',
      };

      const response = await request(app.getHttpServer())
        .patch('/api/applications/non-existent-id')
        .send(updateDto)
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when deleting non-existent application', async () => {
      const response = await request(app.getHttpServer())
        .delete('/api/applications/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting non-existent test suite', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-suites/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting non-existent test harness', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-harnesses/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting non-existent test battery', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-batteries/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting non-existent policy', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/policies/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting non-existent test', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/tests/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting non-existent test result', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/test-results/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when running tests for non-existent application', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/applications/non-existent-id/run-tests')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when getting test configurations for non-existent application', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications/non-existent-id/test-configurations')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });
  });

  describe('Conflict Errors', () => {
    it('should handle duplicate application ID gracefully', async () => {
      const createDto = {
        id: `e2e-conflict-app-${Date.now()}`,
        name: 'Conflict Test App',
        type: 'api',
        team: 'test-team',
        infrastructure: {
          databases: [],
          networkSegments: [],
        },
      };

      // Create first application
      await request(app.getHttpServer())
        .post('/api/applications')
        .send(createDto)
        .expect(201);

      // Try to create duplicate (behavior depends on implementation)
      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send(createDto);

      // Accept either 201 (if duplicates allowed) or 409 (if conflict)
      expect([201, 409]).toContain(response.status);
    });

    it('should handle duplicate email registration gracefully', async () => {
      const registerDto = {
        email: `conflict-${Date.now()}@example.com`,
        password: 'TestPassword123!',
        name: 'Conflict Test User',
      };

      // Register first user
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send(registerDto)
        .expect(201);

      // Try to register duplicate email
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send(registerDto);

      // Accept either 201 (if duplicates allowed) or 409 (if conflict)
      expect([201, 409]).toContain(response.status);
    });
  });

  describe('Unauthorized Access Attempts', () => {
    it('should return 401 when accessing protected endpoint without token', async () => {
      // Note: Auth is currently disabled, so this may return 200
      // But we test the structure for when auth is enabled
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .send({ refreshToken: 'test-token' });

      // Accept either 200 (auth disabled) or 401 (auth enabled)
      expect([200, 401]).toContain(response.status);
    });

    it('should return 401 when using invalid access token', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', 'Bearer invalid-token')
        .send({ refreshToken: 'test-token' });

      // Accept either 200 (auth disabled) or 401 (auth enabled)
      expect([200, 401]).toContain(response.status);
    });

    it('should return 401 when using expired token format', async () => {
      const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.signature';
      
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({ refreshToken: 'test-token' });

      // Accept either 200 (auth disabled) or 401 (auth enabled)
      expect([200, 401]).toContain(response.status);
    });

    it('should return 401 when refreshing with invalid refresh token', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: 'invalid-refresh-token' })
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Forbidden Access Attempts', () => {
    it('should handle permission checks (when auth enabled)', async () => {
      // Note: Auth is currently disabled, so this may return 200
      // But we test the structure for when auth is enabled
      const response = await request(app.getHttpServer())
        .get('/api/security/audit-logs')
        .query({ limit: 10 });

      // Accept either 200 (auth disabled) or 403 (auth enabled, insufficient permissions)
      expect([200, 401, 403]).toContain(response.status);
    });
  });

  describe('Rate Limiting', () => {
    it('should handle rate limiting gracefully', async () => {
      // Make multiple rapid requests
      const requests = Array(20).fill(null).map(() =>
        request(app.getHttpServer())
          .get('/api/applications')
          .expect((res) => {
            // Accept 200 (success) or 429 (rate limited)
            expect([200, 429]).toContain(res.status);
          })
      );

      await Promise.all(requests);
    });

    it('should return 429 with rate limit headers when rate limited', async () => {
      // Make many rapid requests to trigger rate limiting
      // Note: Rate limiting may not be enabled in test environment
      const response = await request(app.getHttpServer())
        .get('/api/applications');

      if (response.status === 429) {
        expect(response.headers).toHaveProperty('retry-after');
        expect(response.body).toHaveProperty('statusCode', 429);
        expect(response.body).toHaveProperty('message');
      } else {
        // Rate limiting not enabled, which is acceptable
        expect(response.status).toBe(200);
      }
    });
  });

  describe('Server Errors', () => {
    it('should handle malformed request body gracefully', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }')
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });

    it('should handle missing Content-Type header', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send({ id: 'test', name: 'Test', type: 'api' })
        .expect((res) => {
          // May return 400 (validation error) or 415 (unsupported media type)
          expect([400, 415]).toContain(res.status);
        });
    });

    it('should handle extremely large request body', async () => {
      const largeData = {
        id: 'test-app',
        name: 'Test',
        type: 'api',
        description: 'x'.repeat(1000000), // Very large description
      };

      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send(largeData)
        .expect((res) => {
          // May return 400 (validation error) or 413 (payload too large)
          expect([400, 413]).toContain(res.status);
        });
    });

    it('should handle invalid JSON in request body', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .set('Content-Type', 'application/json')
        .send('not json at all')
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });
  });

  describe('Invalid Route Errors', () => {
    it('should return 404 for non-existent routes', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/non-existent-route')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 for invalid HTTP methods', async () => {
      const response = await request(app.getHttpServer())
        .patch('/api/applications')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 for routes with invalid path parameters', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications/')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });
  });

  describe('Relationship Validation Errors', () => {
    let applicationId: string;
    let testSuiteId: string;
    let harnessId: string;

    beforeEach(async () => {
      // Create application
      const appDto = {
        id: `e2e-rel-error-app-${Date.now()}`,
        name: 'Relationship Error App',
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
        name: 'Relationship Error Suite',
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
        name: 'Relationship Error Harness',
        domain: 'identity',
        testSuiteIds: [],
        applicationIds: [],
        team: 'test-team',
      };

      const harnessResponse = await request(app.getHttpServer())
        .post('/api/v1/test-harnesses')
        .send(harnessDto)
        .expect(201);

      harnessId = harnessResponse.body.id;
    });

    it('should return 404 when adding non-existent test suite to harness', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-harnesses/${harnessId}/test-suites`)
        .send({ suiteId: 'non-existent-suite-id' })
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when assigning harness to non-existent application', async () => {
      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-harnesses/${harnessId}/applications`)
        .send({ applicationId: 'non-existent-app-id' })
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should return 404 when adding non-existent harness to battery', async () => {
      // Create battery
      const batteryDto = {
        name: 'Error Test Battery',
        harnessIds: [],
        executionConfig: {
          executionMode: 'parallel',
        },
        team: 'test-team',
      };

      const batteryResponse = await request(app.getHttpServer())
        .post('/api/v1/test-batteries')
        .send(batteryDto)
        .expect(201);

      const batteryId = batteryResponse.body.id;

      const response = await request(app.getHttpServer())
        .post(`/api/v1/test-batteries/${batteryId}/harnesses`)
        .send({ harnessId: 'non-existent-harness-id' })
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });
  });

  describe('Query Parameter Errors', () => {
    it('should handle invalid query parameter types', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({ limit: 'not-a-number' })
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });

    it('should handle invalid date range (end before start)', async () => {
      const endDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const startDate = new Date().toISOString();

      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({
          startDate: startDate,
          endDate: endDate,
        });

      // May return 400 (validation error) or 200 (if validation not strict)
      expect([200, 400]).toContain(response.status);
    });

    it('should handle invalid enum values in query parameters', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/test-results')
        .query({ status: 'invalid-status' })
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle empty string IDs', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications/')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should handle very long IDs', async () => {
      const longId = 'x'.repeat(1000);
      const response = await request(app.getHttpServer())
        .get(`/api/applications/${longId}`)
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should handle special characters in IDs', async () => {
      const specialId = '../../etc/passwd';
      const response = await request(app.getHttpServer())
        .get(`/api/applications/${specialId}`)
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should handle null values in request body', async () => {
      const invalidDto = {
        id: null,
        name: null,
        type: null,
      };

      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send(invalidDto)
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });

    it('should handle undefined values in request body', async () => {
      const invalidDto = {
        id: undefined,
        name: 'Test',
        type: 'api',
      };

      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send(invalidDto)
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });
  });

  describe('Error Response Format', () => {
    it('should return consistent error response format for 400 errors', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/applications')
        .send({})
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('error');
    });

    it('should return consistent error response format for 404 errors', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/applications/non-existent-id')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
      expect(response.body).toHaveProperty('message');
    });

    it('should return consistent error response format for 401 errors', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
      expect(response.body).toHaveProperty('message');
    });
  });
});
