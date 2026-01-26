/**
 * Agent Tests Integration Tests
 * 
 * Tests the full workflow of agent access control testing
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Agent Tests Integration (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /api/agent-tests/delegated-access', () => {
    it('should run delegated access tests', () => {
      return request(app.getHttpServer())
        .post('/api/agent-tests/delegated-access')
        .send({
          agentId: 'agent-001',
          userContext: {
            userId: 'user-123',
            email: 'user@example.com',
            role: 'researcher',
            permissions: ['read:emails'],
          },
          resources: [
            {
              id: 'inbox-123',
              type: 'emails',
              attributes: {},
            },
          ],
          actions: ['read'],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('agentId', 'agent-001');
          expect(res.body).toHaveProperty('testType', 'delegated-access');
          expect(res.body).toHaveProperty('results');
          expect(res.body).toHaveProperty('summary');
        });
    });

    it('should validate required fields', () => {
      return request(app.getHttpServer())
        .post('/api/agent-tests/delegated-access')
        .send({
          agentId: 'agent-001',
          // Missing userContext
        })
        .expect(400);
    });
  });

  describe('POST /api/agent-tests/direct-access', () => {
    it('should run direct access tests', () => {
      return request(app.getHttpServer())
        .post('/api/agent-tests/direct-access')
        .send({
          agentId: 'agent-002',
          agentType: 'autonomous',
          resources: [
            {
              id: 'logs-123',
              type: 'logs',
              attributes: {},
            },
          ],
          actions: ['read'],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('agentId', 'agent-002');
          expect(res.body).toHaveProperty('testType', 'direct-access');
        });
    });
  });

  describe('GET /api/agent-tests/audit-trail/:agentId', () => {
    it('should get audit trail for agent', () => {
      return request(app.getHttpServer())
        .get('/api/agent-tests/audit-trail/agent-001')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('agentId', 'agent-001');
          expect(res.body).toHaveProperty('auditTrail');
          expect(res.body).toHaveProperty('totalEntries');
        });
    });

    it('should filter audit trail by date range', () => {
      return request(app.getHttpServer())
        .get('/api/agent-tests/audit-trail/agent-001')
        .send({
          startDate: '2024-01-01',
          endDate: '2024-12-31',
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('filters');
        });
    });
  });

  describe('POST /api/agent-tests/multi-service', () => {
    it('should test multi-service access', () => {
      return request(app.getHttpServer())
        .post('/api/agent-tests/multi-service')
        .send({
          agentId: 'agent-003',
          agentType: 'delegated',
          userContext: {
            userId: 'user-123',
            permissions: ['read:emails', 'read:documents'],
          },
          services: [
            {
              serviceId: 'email-service',
              resource: {
                id: 'inbox-123',
                type: 'emails',
                attributes: {},
              },
              action: 'read',
              expectedAllowed: true,
            },
            {
              serviceId: 'document-service',
              resource: {
                id: 'doc-123',
                type: 'documents',
                attributes: {},
              },
              action: 'read',
              expectedAllowed: true,
            },
          ],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('agentId', 'agent-003');
          expect(res.body).toHaveProperty('testType', 'multi-service');
        });
    });
  });

  describe('POST /api/agent-tests/dynamic-access', () => {
    it('should test dynamic access scenarios', () => {
      return request(app.getHttpServer())
        .post('/api/agent-tests/dynamic-access')
        .send({
          agentId: 'agent-004',
          agentType: 'delegated',
          userContext: {
            userId: 'user-123',
            permissions: ['read:documents'],
          },
          scenarios: [
            {
              name: 'Office access',
              context: {
                location: 'office',
                timeOfDay: '14:30',
              },
              requestedPermission: 'read:documents',
              expectedGranted: true,
            },
          ],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('agentId', 'agent-004');
          expect(res.body).toHaveProperty('testType', 'dynamic-access');
          expect(res.body).toHaveProperty('results');
        });
    });
  });

  describe('POST /api/agent-tests/audit-trail/validate', () => {
    it('should validate audit trail', () => {
      return request(app.getHttpServer())
        .post('/api/agent-tests/audit-trail/validate')
        .send({
          agentId: 'agent-001',
          agentType: 'delegated',
          userId: 'user-123',
          actions: [
            {
              serviceId: 'email-service',
              action: 'read',
              resourceId: 'inbox-123',
              resourceType: 'emails',
              timestamp: new Date().toISOString(),
              expectedLogged: true,
            },
          ],
          auditSources: ['source-1'],
          retentionPeriod: 90,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('agentId', 'agent-001');
          expect(res.body).toHaveProperty('validationResult');
        });
    });
  });
});
