/**
 * E2E Tests for API Gateway Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { APIGatewayPolicy, APIRequest } from '../../core/types';

describe('API Gateway Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  const validPolicy: APIGatewayPolicy = {
    id: 'policy-123',
    name: 'Test Policy',
    endpoint: '/api/test',
    method: 'GET',
    rules: [],
  };

  const validRequest: APIRequest = {
    endpoint: '/api/test',
    method: 'GET',
    headers: {},
    body: {},
  };

  describe('POST /api/api-gateway/test-gateway-policy', () => {
    it('should return gateway policy test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-gateway-policy')
        .send({ policy: validPolicy, request: validRequest })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType', 'access-control');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing policy', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-gateway-policy')
        .send({ request: validRequest })
        .expect(400);
    });

    it('should return 400 with missing request', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-gateway-policy')
        .send({ policy: validPolicy })
        .expect(400);
    });
  });

  describe('POST /api/api-gateway/test-rate-limiting', () => {
    it('should return rate limiting test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-rate-limiting')
        .send({ endpoint: '/api/test', requests: 100 })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('endpoint');
          expect(res.body).toHaveProperty('blocked');
        });
    });

    it('should return 400 with missing endpoint', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-rate-limiting')
        .send({ requests: 100 })
        .expect(400);
    });

    it('should return 400 with missing requests', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-rate-limiting')
        .send({ endpoint: '/api/test' })
        .expect(400);
    });
  });

  describe('POST /api/api-gateway/test-api-versioning', () => {
    it('should return API versioning test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-api-versioning')
        .send({ version: 'v1', endpoint: '/api/test' })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing version', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-api-versioning')
        .send({ endpoint: '/api/test' })
        .expect(400);
    });

    it('should return 400 with missing endpoint', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-api-versioning')
        .send({ version: 'v1' })
        .expect(400);
    });
  });

  describe('POST /api/api-gateway/test-service-auth', () => {
    it('should return service auth test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-service-auth')
        .send({ source: 'service-1', target: 'service-2' })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('authMethod');
          expect(res.body).toHaveProperty('authenticated');
        });
    });

    it('should return 400 with missing source', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-service-auth')
        .send({ target: 'service-2' })
        .expect(400);
    });

    it('should return 400 with missing target', () => {
      return request(app.getHttpServer())
        .post('/api/api-gateway/test-service-auth')
        .send({ source: 'service-1' })
        .expect(400);
    });
  });
});


