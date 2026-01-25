/**
 * E2E Tests for Identity Provider Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { User } from '../../heimdall-framework/core/types';

describe('Identity Provider Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  const validUser: User = {
    id: 'user-123',
    email: 'test@example.com',
    role: 'viewer',
    attributes: {},
  };

  describe('POST /api/identity-providers/test-ad-group', () => {
    it('should return AD group test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-ad-group')
        .send({ user: validUser, group: 'test-group' })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-ad-group')
        .send({ group: 'test-group' })
        .expect(400);
    });

    it('should return 400 with missing group', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-ad-group')
        .send({ user: validUser })
        .expect(400);
    });
  });

  describe('POST /api/identity-providers/test-okta-policy', () => {
    it('should return Okta policy test with valid policy', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-okta-policy')
        .send({
          policy: {
            policyId: 'okta-policy-123',
            policyName: 'Test Policy',
            synchronized: true,
            lastSync: new Date(),
            violations: [],
          },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing policy', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-okta-policy')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-providers/test-auth0-policy', () => {
    it('should return Auth0 policy test with valid policy', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-auth0-policy')
        .send({ policy: { id: 'auth0-policy-123' } })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing policy', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-auth0-policy')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-providers/test-azure-ad-conditional-access', () => {
    it('should return Azure AD test with valid policy', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-azure-ad-conditional-access')
        .send({
          policy: {
            id: 'azure-policy-123',
            name: 'Test Policy',
            conditions: {},
            grantControls: { requireMfa: true },
          },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing policy', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-azure-ad-conditional-access')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-providers/test-gcp-iam-binding', () => {
    it('should return GCP IAM binding test with valid binding', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-gcp-iam-binding')
        .send({
          binding: {
            resource: 'projects/test-project',
            role: 'roles/viewer',
            members: ['user:test@example.com'],
          },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing binding', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/test-gcp-iam-binding')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-providers/validate-policy-sync', () => {
    it('should return policy sync validation with valid source and target', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/validate-policy-sync')
        .send({
          source: { type: 'okta', config: {} },
          target: { type: 'azure-ad', config: {} },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing source', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/validate-policy-sync')
        .send({ target: { type: 'azure-ad', config: {} } })
        .expect(400);
    });

    it('should return 400 with missing target', () => {
      return request(app.getHttpServer())
        .post('/api/identity-providers/validate-policy-sync')
        .send({ source: { type: 'okta', config: {} } })
        .expect(400);
    });
  });
});
