/**
 * E2E Tests for NIST 800-207 Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { ComplianceAssessment } from '../../heimdall-framework/core/types';

describe('NIST 800-207 Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  const validAssessment: ComplianceAssessment = {
    framework: 'NIST-800-207',
    assessment: {
      id: 'assessment-123',
      timestamp: new Date(),
      pillars: [],
      overallScore: 80,
      gaps: [],
      recommendations: [],
    },
    compliancePercentage: 80,
    compliant: true,
  };

  describe('POST /api/compliance/nist-800-207/assess', () => {
    it('should return compliance assessment with optional assessment', () => {
      return request(app.getHttpServer())
        .post('/api/compliance/nist-800-207/assess')
        .send({ assessment: { id: 'test-assessment' } })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('framework', 'NIST-800-207');
          expect(res.body).toHaveProperty('compliancePercentage');
          expect(res.body).toHaveProperty('compliant');
        });
    });

    it('should return compliance assessment without assessment (optional)', () => {
      return request(app.getHttpServer())
        .post('/api/compliance/nist-800-207/assess')
        .send({})
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('framework', 'NIST-800-207');
        });
    });
  });

  describe('POST /api/compliance/nist-800-207/report', () => {
    it('should return compliance report with valid assessment', () => {
      return request(app.getHttpServer())
        .post('/api/compliance/nist-800-207/report')
        .send({ assessment: validAssessment })
        .expect(200)
        .expect((res) => {
          expect(typeof res.text).toBe('string');
          expect(res.text).toContain('NIST 800-207');
        });
    });

    it('should return 400 with missing assessment', () => {
      return request(app.getHttpServer())
        .post('/api/compliance/nist-800-207/report')
        .send({})
        .expect(400);
    });

    it('should return 400 with invalid assessment (missing framework)', () => {
      return request(app.getHttpServer())
        .post('/api/compliance/nist-800-207/report')
        .send({
          assessment: {
            assessment: {},
          },
        })
        .expect(400);
    });
  });
});
