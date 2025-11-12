/**
 * E2E Tests for Security Gates Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { PullRequest, ABACPolicy, SecurityGateConfig } from '../../core/types';

describe('Security Gates Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  const validPR: PullRequest = {
    id: 'pr-123',
    number: 123,
    author: 'test-user',
    files: ['file1.ts', 'file2.ts'],
    branch: 'feature/test',
    baseBranch: 'main',
  };

  const validPolicy: ABACPolicy = {
    id: 'policy-123',
    name: 'Test Policy',
    description: 'Test policy',
    effect: 'allow',
    conditions: [],
  };

  const validConfig: SecurityGateConfig = {
    requirePolicies: true,
    scanIAC: true,
    scanContainers: false,
    validateK8sRBAC: false,
    failOnThreshold: true,
    severityThreshold: 'high',
    maxFindings: 10,
  };

  describe('POST /api/cicd/security-gates/validate-pre-merge', () => {
    it('should return pre-merge validation with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/cicd/security-gates/validate-pre-merge')
        .send({ pr: validPR, policies: [validPolicy] })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('passed');
          expect(res.body).toHaveProperty('gates');
          expect(res.body).toHaveProperty('findings');
        });
    });

    it('should return 400 with missing pr', () => {
      return request(app.getHttpServer())
        .post('/api/cicd/security-gates/validate-pre-merge')
        .send({ policies: [validPolicy] })
        .expect(400);
    });

    it('should return 400 with missing policies', () => {
      return request(app.getHttpServer())
        .post('/api/cicd/security-gates/validate-pre-merge')
        .send({ pr: validPR })
        .expect(400);
    });
  });

  describe('POST /api/cicd/security-gates/check-gates', () => {
    it('should return security gates check with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/cicd/security-gates/check-gates')
        .send({ pr: validPR, config: validConfig })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('passed');
          expect(res.body).toHaveProperty('gates');
          expect(res.body).toHaveProperty('findings');
          expect(res.body).toHaveProperty('riskScore');
        });
    });

    it('should return 400 with missing pr', () => {
      return request(app.getHttpServer())
        .post('/api/cicd/security-gates/check-gates')
        .send({ config: validConfig })
        .expect(400);
    });

    it('should return 400 with missing config', () => {
      return request(app.getHttpServer())
        .post('/api/cicd/security-gates/check-gates')
        .send({ pr: validPR })
        .expect(400);
    });
  });
});

