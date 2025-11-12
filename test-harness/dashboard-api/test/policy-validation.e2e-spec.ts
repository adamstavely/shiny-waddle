/**
 * E2E Tests for Policy Validation Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { ABACPolicy, Resource } from '../../core/types';

describe('Policy Validation Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  const validPolicy: ABACPolicy = {
    id: 'policy-123',
    name: 'Test Policy',
    description: 'Test policy description',
    effect: 'allow',
    conditions: [],
  };

  const validResource: Resource = {
    id: 'resource-123',
    type: 'dataset',
    attributes: {},
  };

  describe('POST /api/policy-validation/detect-conflicts', () => {
    it('should return conflicts with valid policies', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/detect-conflicts')
        .send({ policies: [validPolicy] })
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });

    it('should return 400 with missing policies', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/detect-conflicts')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/policy-validation/analyze-coverage', () => {
    it('should return coverage analysis with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/analyze-coverage')
        .send({
          resources: [validResource],
          policies: [validPolicy],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('totalResources');
          expect(res.body).toHaveProperty('coveragePercentage');
        });
    });

    it('should return 400 with missing resources', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/analyze-coverage')
        .send({ policies: [validPolicy] })
        .expect(400);
    });

    it('should return 400 with missing policies', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/analyze-coverage')
        .send({ resources: [validResource] })
        .expect(400);
    });
  });

  describe('POST /api/policy-validation/test-performance', () => {
    it('should return performance metrics with valid policy', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/test-performance')
        .send({ policy: validPolicy })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('policyId');
          expect(res.body).toHaveProperty('averageTime');
        });
    });

    it('should return 400 with missing policy', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/test-performance')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/policy-validation/run-regression', () => {
    it('should return regression test results with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/run-regression')
        .send({
          baselinePolicies: [validPolicy],
          currentPolicies: [validPolicy],
          testCases: [],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('regressions');
        });
    });

    it('should return 400 with missing baseline policies', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/run-regression')
        .send({
          currentPolicies: [validPolicy],
          testCases: [],
        })
        .expect(400);
    });
  });

  describe('POST /api/policy-validation/simulate-policy', () => {
    it('should return simulation results with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/simulate-policy')
        .send({
          policy: validPolicy,
          testCases: [],
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('policyId');
        });
    });

    it('should return 400 with missing policy', () => {
      return request(app.getHttpServer())
        .post('/api/policy-validation/simulate-policy')
        .send({ testCases: [] })
        .expect(400);
    });
  });
});

