/**
 * E2E Tests for Identity Lifecycle Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { User, PAMRequest } from '../../core/types';

describe('Identity Lifecycle Controller (e2e)', () => {
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

  const validPAMRequest: PAMRequest = {
    userId: 'user-123',
    resource: 'resource-123',
    duration: 60,
    reason: 'Emergency access',
    approver: 'admin-123',
  };

  describe('POST /api/identity-lifecycle/test-onboarding', () => {
    it('should return onboarding test result with valid user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-onboarding')
        .send({ user: validUser })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType', 'access-control');
          expect(res.body).toHaveProperty('testName');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-onboarding')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-lifecycle/test-role-change', () => {
    it('should return role change test result with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-role-change')
        .send({ user: validUser, newRole: 'admin' })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-role-change')
        .send({ newRole: 'admin' })
        .expect(400);
    });

    it('should return 400 with missing newRole', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-role-change')
        .send({ user: validUser })
        .expect(400);
    });
  });

  describe('POST /api/identity-lifecycle/test-offboarding', () => {
    it('should return offboarding test result with valid user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-offboarding')
        .send({ user: validUser })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-offboarding')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-lifecycle/validate-credential-rotation', () => {
    it('should return credential rotation validation with valid user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/validate-credential-rotation')
        .send({ user: validUser })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/validate-credential-rotation')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-lifecycle/test-mfa-enforcement', () => {
    it('should return MFA enforcement test with valid user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-mfa-enforcement')
        .send({ user: validUser })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing user', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-mfa-enforcement')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-lifecycle/test-jit-access', () => {
    it('should return JIT access test with valid request', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-jit-access')
        .send({ request: validPAMRequest })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing request', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-jit-access')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/identity-lifecycle/test-break-glass', () => {
    it('should return break-glass test with valid request', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-break-glass')
        .send({ request: { ...validPAMRequest, emergency: true } })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing request', () => {
      return request(app.getHttpServer())
        .post('/api/identity-lifecycle/test-break-glass')
        .send({})
        .expect(400);
    });
  });
});

