/**
 * E2E Tests for Network Policy Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';
import { FirewallRule, NetworkSegment } from '../../core/types';

describe('Network Policy Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  const validFirewallRule: FirewallRule = {
    id: 'rule-1',
    name: 'test-rule',
    source: '10.0.0.0/8',
    destination: '192.168.1.0/24',
    protocol: 'tcp' as const,
    port: 443,
    action: 'allow' as const,
    enabled: true,
  };

  const validSegment: NetworkSegment = {
    id: 'segment-1',
    name: 'Test Segment',
    services: ['service-1'],
    allowedConnections: ['segment-2'],
    deniedConnections: ['segment-3'],
  };

  describe('POST /api/network-policy/test-firewall-rules', () => {
    it('should return firewall rule test results with valid rules', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-firewall-rules')
        .send({ rules: [validFirewallRule] })
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
          if (res.body.length > 0) {
            expect(res.body[0]).toHaveProperty('testType');
            expect(res.body[0]).toHaveProperty('passed');
          }
        });
    });

    it('should return 400 with missing rules', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-firewall-rules')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/network-policy/test-service-to-service', () => {
    it('should return service-to-service test with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-service-to-service')
        .send({ source: 'service-1', target: 'service-2' })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing source', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-service-to-service')
        .send({ target: 'service-2' })
        .expect(400);
    });

    it('should return 400 with missing target', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-service-to-service')
        .send({ source: 'service-1' })
        .expect(400);
    });
  });

  describe('POST /api/network-policy/validate-segmentation', () => {
    it('should return segmentation validation with valid segments', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/validate-segmentation')
        .send({ segments: [validSegment] })
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });

    it('should return 400 with missing segments', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/validate-segmentation')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/network-policy/test-service-mesh-policies', () => {
    it('should return service mesh test with valid config', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-service-mesh-policies')
        .send({
          config: {
            type: 'istio',
            controlPlaneEndpoint: 'https://istio-control-plane:8080',
          },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('testType');
          expect(res.body).toHaveProperty('passed');
        });
    });

    it('should return 400 with missing config', () => {
      return request(app.getHttpServer())
        .post('/api/network-policy/test-service-mesh-policies')
        .send({})
        .expect(400);
    });
  });
});

