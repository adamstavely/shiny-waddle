/**
 * E2E Tests for RLS/CLS Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { DatabaseConfig, TestQuery, User, DynamicMaskingRule } from '../../heimdall-framework/core/types';

describe('RLS/CLS Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  const validDatabaseConfig: DatabaseConfig = {
    type: 'postgresql',
    host: 'localhost',
    port: 5432,
    database: 'test_db',
    username: 'test_user',
    password: 'test_password',
  };

  const validUser: User = {
    id: 'user-123',
    email: 'test@example.com',
    role: 'viewer',
    attributes: {},
  };

  const validQuery: TestQuery = {
    name: 'test-query',
    sql: 'SELECT * FROM users',
  };

  describe('POST /api/rls-cls/test-rls-coverage', () => {
    it('should return RLS coverage with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-rls-coverage')
        .send({ database: validDatabaseConfig })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('database');
          expect(res.body).toHaveProperty('tablesWithRLS');
          expect(res.body).toHaveProperty('tablesWithoutRLS');
          expect(res.body).toHaveProperty('coveragePercentage');
        });
    });

    it('should return 400 with missing database', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-rls-coverage')
        .send({})
        .expect(400);
    });

    it('should return 400 with invalid database config', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-rls-coverage')
        .send({ database: { type: 'invalid' } })
        .expect(400);
    });
  });

  describe('POST /api/rls-cls/test-cls-coverage', () => {
    it('should return CLS coverage with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-cls-coverage')
        .send({ database: validDatabaseConfig })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('database');
          expect(res.body).toHaveProperty('columnsWithCLS');
          expect(res.body).toHaveProperty('columnsWithoutCLS');
          expect(res.body).toHaveProperty('coveragePercentage');
        });
    });

    it('should return 400 with missing database', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-cls-coverage')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/rls-cls/test-dynamic-masking', () => {
    const validMaskingRules: DynamicMaskingRule[] = [
      {
        table: 'users',
        column: 'email',
        maskingType: 'partial' as const,
        applicableRoles: ['viewer'],
      },
    ];

    it('should return masking test result with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-dynamic-masking')
        .send({
          query: validQuery,
          user: validUser,
          maskingRules: validMaskingRules,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType', 'access-control');
          expect(res.body).toHaveProperty('testName');
          expect(res.body).toHaveProperty('passed');
          expect(res.body).toHaveProperty('details');
        });
    });

    it('should return 400 with missing query', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-dynamic-masking')
        .send({
          user: validUser,
          maskingRules: validMaskingRules,
        })
        .expect(400);
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-dynamic-masking')
        .send({
          query: validQuery,
          maskingRules: validMaskingRules,
        })
        .expect(400);
    });

    it('should return 400 with missing masking rules', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-dynamic-masking')
        .send({
          query: validQuery,
          user: validUser,
        })
        .expect(400);
    });
  });

  describe('POST /api/rls-cls/test-cross-tenant-isolation', () => {
    it('should return isolation test result with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-cross-tenant-isolation')
        .send({
          tenant1: 'tenant-1',
          tenant2: 'tenant-2',
          testQueries: [validQuery],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('tenant1');
          expect(res.body).toHaveProperty('tenant2');
          expect(res.body).toHaveProperty('isolationVerified');
          expect(res.body).toHaveProperty('testQueries');
          expect(res.body).toHaveProperty('violations');
        });
    });

    it('should return 400 with missing tenant1', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-cross-tenant-isolation')
        .send({
          tenant2: 'tenant-2',
          testQueries: [validQuery],
        })
        .expect(400);
    });

    it('should return 400 with missing tenant2', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-cross-tenant-isolation')
        .send({
          tenant1: 'tenant-1',
          testQueries: [validQuery],
        })
        .expect(400);
    });

    it('should return 400 with missing test queries', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-cross-tenant-isolation')
        .send({
          tenant1: 'tenant-1',
          tenant2: 'tenant-2',
        })
        .expect(400);
    });
  });

  describe('POST /api/rls-cls/test-policy-bypass', () => {
    it('should return bypass test result with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-policy-bypass')
        .send({
          userId: 'user-123',
          resourceId: 'resource-123',
          resourceType: 'dataset',
        })
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
          if (res.body.length > 0) {
            expect(res.body[0]).toHaveProperty('testType');
            expect(res.body[0]).toHaveProperty('testName');
            expect(res.body[0]).toHaveProperty('passed');
          }
        });
    });

    it('should return 400 with missing userId', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-policy-bypass')
        .send({
          resourceId: 'resource-123',
          resourceType: 'dataset',
        })
        .expect(400);
    });

    it('should return 400 with missing resourceId', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-policy-bypass')
        .send({
          userId: 'user-123',
          resourceType: 'dataset',
        })
        .expect(400);
    });

    it('should return 400 with missing resourceType', () => {
      return request(app.getHttpServer())
        .post('/api/rls-cls/test-policy-bypass')
        .send({
          userId: 'user-123',
          resourceId: 'resource-123',
        })
        .expect(400);
    });
  });
});

