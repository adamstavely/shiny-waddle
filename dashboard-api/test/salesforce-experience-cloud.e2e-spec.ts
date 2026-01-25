/**
 * E2E Tests for Salesforce Experience Cloud Controller
 */

import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { createE2EApp } from './jest-e2e.setup';

describe('Salesforce Experience Cloud Controller (e2e)', () => {
  let app: INestApplication;
  let configId: string;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
  });

  describe('POST /api/salesforce-experience-cloud/configs', () => {
    it('should create a configuration with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/configs')
        .send({
          name: 'Test Configuration',
          url: 'https://example.force.com',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('id');
          expect(res.body.name).toBe('Test Configuration');
          expect(res.body.url).toBe('https://example.force.com');
          expect(res.body).toHaveProperty('createdAt');
          expect(res.body).toHaveProperty('updatedAt');
          configId = res.body.id;
        });
    });

    it('should create a configuration with all optional fields', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/configs')
        .send({
          name: 'Full Configuration',
          url: 'https://test.force.com',
          cookies: 'sid=test123;',
          objectList: ['Account', 'Contact'],
          app: '/myApp',
          aura: '/aura',
          timeout: 300000,
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.objectList).toEqual(['Account', 'Contact']);
          expect(res.body.app).toBe('/myApp');
          expect(res.body.aura).toBe('/aura');
        });
    });

    it('should return 400 with missing name', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/configs')
        .send({
          url: 'https://example.force.com',
        })
        .expect(400);
    });

    it('should return 400 with missing url', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/configs')
        .send({
          name: 'Test Configuration',
        })
        .expect(400);
    });

    it('should return 400 with invalid URL', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/configs')
        .send({
          name: 'Test Configuration',
          url: 'not-a-valid-url',
        })
        .expect(400);
    });
  });

  describe('GET /api/salesforce-experience-cloud/configs', () => {
    it('should return list of configurations', () => {
      return request(app.getHttpServer())
        .get('/api/salesforce-experience-cloud/configs')
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });
  });

  describe('GET /api/salesforce-experience-cloud/configs/:id', () => {
    it('should return configuration by ID', () => {
      return request(app.getHttpServer())
        .get(`/api/salesforce-experience-cloud/configs/${configId}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.id).toBe(configId);
          expect(res.body).toHaveProperty('name');
          expect(res.body).toHaveProperty('url');
        });
    });

    it('should return 404 for non-existent config', () => {
      return request(app.getHttpServer())
        .get('/api/salesforce-experience-cloud/configs/non-existent-id')
        .expect(404);
    });
  });

  describe('PATCH /api/salesforce-experience-cloud/configs/:id', () => {
    it('should update configuration', () => {
      return request(app.getHttpServer())
        .patch(`/api/salesforce-experience-cloud/configs/${configId}`)
        .send({
          name: 'Updated Configuration',
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.name).toBe('Updated Configuration');
          expect(res.body).toHaveProperty('updatedAt');
        });
    });

    it('should return 404 for non-existent config', () => {
      return request(app.getHttpServer())
        .patch('/api/salesforce-experience-cloud/configs/non-existent-id')
        .send({
          name: 'Updated',
        })
        .expect(404);
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/guest-access', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/guest-access')
        .send({})
        .expect(400);
    });

    it('should return 404 with non-existent configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/guest-access')
        .send({
          configId: 'non-existent-id',
        })
        .expect(404);
    });

    // Note: Actual test execution would require aura-inspector to be installed
    // This test would fail in CI without proper setup, so we skip the success case
    it.skip('should run guest access test with valid configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/guest-access')
        .send({
          configId,
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('id');
          expect(res.body.testType).toBe('guest-access');
          expect(res.body.configId).toBe(configId);
        });
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/authenticated-access', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/authenticated-access')
        .send({})
        .expect(400);
    });

    it('should accept optional cookies override', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/authenticated-access')
        .send({
          configId: 'non-existent-id',
          cookies: 'custom-cookies',
        })
        .expect(404); // Config not found, but cookies were accepted
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/graphql', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/graphql')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/self-registration', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/self-registration')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/record-lists', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/record-lists')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/home-urls', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/home-urls')
        .send({})
        .expect(400);
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/object-access', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/object-access')
        .send({})
        .expect(400);
    });

    it('should return 400 with missing objects array', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/object-access')
        .send({
          configId,
        })
        .expect(400);
    });

    it('should return 400 with empty objects array', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/object-access')
        .send({
          configId,
          objects: [],
        })
        .expect(400);
    });
  });

  describe('POST /api/salesforce-experience-cloud/tests/full-audit', () => {
    it('should return 400 with missing configId', () => {
      return request(app.getHttpServer())
        .post('/api/salesforce-experience-cloud/tests/full-audit')
        .send({})
        .expect(400);
    });
  });

  describe('GET /api/salesforce-experience-cloud/results', () => {
    it('should return list of results', () => {
      return request(app.getHttpServer())
        .get('/api/salesforce-experience-cloud/results')
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });
  });

  describe('DELETE /api/salesforce-experience-cloud/configs/:id', () => {
    it('should delete configuration', () => {
      return request(app.getHttpServer())
        .delete(`/api/salesforce-experience-cloud/configs/${configId}`)
        .expect(204);
    });

    it('should return 404 for non-existent config', () => {
      return request(app.getHttpServer())
        .delete('/api/salesforce-experience-cloud/configs/non-existent-id')
        .expect(404);
    });
  });

  describe('GET /api/salesforce-experience-cloud', () => {
    it('should return summary', () => {
      return request(app.getHttpServer())
        .get('/api/salesforce-experience-cloud')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('configs');
          expect(res.body).toHaveProperty('results');
          expect(typeof res.body.configs).toBe('number');
          expect(typeof res.body.results).toBe('number');
        });
    });
  });
});
