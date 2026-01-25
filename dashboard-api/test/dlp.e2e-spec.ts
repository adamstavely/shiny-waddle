/**
 * E2E Tests for DLP Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { User, DataOperation, TestQuery } from '../../heimdall-framework/core/types';

describe('DLP Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  const validUser: User = {
    id: 'user-123',
    email: 'test@example.com',
    role: 'viewer',
    attributes: {},
  };

  const validDataOperation: DataOperation = {
    type: 'export',
    resource: { id: 'resource-1', type: 'dataset', attributes: {} },
    data: { test: 'data' },
  };

  const validQuery: TestQuery = {
    name: 'test-query',
    sql: 'SELECT * FROM users',
  };

  describe('POST /api/dlp/test-exfiltration', () => {
    it('should return exfiltration test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-exfiltration')
        .send({ user: validUser, dataOperation: validDataOperation })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType', 'data-behavior');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-exfiltration')
        .send({ dataOperation: validDataOperation })
        .expect(400);
    });

    it('should return 400 with missing dataOperation', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-exfiltration')
        .send({ user: validUser })
        .expect(400);
    });
  });

  describe('POST /api/dlp/validate-api-response', () => {
    it('should return API response validation with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/validate-api-response')
        .send({
          apiResponse: { id: '123', name: 'test' },
          allowedFields: ['id', 'name'],
          piiFields: ['email', 'ssn'],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing apiResponse', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/validate-api-response')
        .send({
          allowedFields: ['id'],
          piiFields: ['email'],
        })
        .expect(400);
    });

    it('should return 400 with missing allowedFields', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/validate-api-response')
        .send({
          apiResponse: {},
          piiFields: ['email'],
        })
        .expect(400);
    });
  });

  describe('POST /api/dlp/test-query-validation', () => {
    it('should return query validation with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-query-validation')
        .send({
          query: validQuery,
          user: validUser,
          expectedFields: ['id', 'name'],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing query', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-query-validation')
        .send({
          user: validUser,
          expectedFields: ['id'],
        })
        .expect(400);
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-query-validation')
        .send({
          query: validQuery,
          expectedFields: ['id'],
        })
        .expect(400);
    });
  });

  describe('POST /api/dlp/test-bulk-export', () => {
    it('should return bulk export test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-bulk-export')
        .send({
          user: validUser,
          exportRequest: {
            type: 'csv',
            recordCount: 1000,
          },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-bulk-export')
        .send({
          exportRequest: {
            type: 'csv',
            recordCount: 1000,
          },
        })
        .expect(400);
    });

    it('should return 400 with missing exportRequest', () => {
      return request(app.getHttpServer())
        .post('/api/dlp/test-bulk-export')
        .send({ user: validUser })
        .expect(400);
    });
  });
});

