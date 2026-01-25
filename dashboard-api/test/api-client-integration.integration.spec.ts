/**
 * Integration Tests for API Client (Fetch-based)
 * 
 * Tests the fetch-based API client used in real-system-integration:
 * 1. API request execution
 * 2. Error handling
 * 3. Authentication header generation
 * 4. Response parsing
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp } from './integration-setup';
import { RealSystemIntegration, APIConnection, TestQuery } from '../../../heimdall-framework/services/real-system-integration';
import nock from 'nock';

describe('API Client Integration Tests (Fetch-based)', () => {
  let app: INestApplication;
  let apiClient: RealSystemIntegration;

  beforeAll(async () => {
    app = await createIntegrationApp();
    apiClient = new RealSystemIntegration();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    nock.cleanAll();
  });

  afterEach(() => {
    nock.isDone();
  });

  describe('API Request Execution', () => {
    it('should execute GET request successfully', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/users',
        httpMethod: 'GET',
      };

      // Mock successful GET request
      nock('https://api.example.com')
        .get('/users')
        .reply(200, {
          users: [
            { id: 1, name: 'User 1' },
            { id: 2, name: 'User 2' },
          ],
        });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
      expect(response.body.users).toBeDefined();
      expect(response.body.users.length).toBe(2);
    });

    it('should execute POST request successfully', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/users',
        httpMethod: 'POST',
        requestBody: {
          name: 'New User',
          email: 'user@example.com',
        },
      };

      // Mock successful POST request
      nock('https://api.example.com')
        .post('/users', {
          name: 'New User',
          email: 'user@example.com',
        })
        .reply(201, {
          id: 3,
          name: 'New User',
          email: 'user@example.com',
        });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(201);
      expect(response.body.id).toBe(3);
      expect(response.body.name).toBe('New User');
    });
  });

  describe('Authentication Header Generation', () => {
    it('should add Bearer token authentication header', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
        authentication: {
          type: 'bearer',
          credentials: {
            token: 'test-token-123',
          },
        },
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/protected',
        httpMethod: 'GET',
      };

      // Mock request with Bearer token
      nock('https://api.example.com')
        .get('/protected')
        .matchHeader('Authorization', 'Bearer test-token-123')
        .reply(200, { data: 'protected data' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
    });

    it('should add Basic authentication header', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/protected',
        httpMethod: 'GET',
      };

      // Mock request with Basic auth
      const expectedAuth = Buffer.from('testuser:testpass').toString('base64');
      nock('https://api.example.com')
        .get('/protected')
        .matchHeader('Authorization', `Basic ${expectedAuth}`)
        .reply(200, { data: 'protected data' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
    });

    it('should add API key authentication header', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
        authentication: {
          type: 'api-key',
          credentials: {
            apiKey: 'api-key-123',
          },
        },
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/protected',
        httpMethod: 'GET',
      };

      // Mock request with API key
      nock('https://api.example.com')
        .get('/protected')
        .matchHeader('X-API-Key', 'api-key-123')
        .reply(200, { data: 'protected data' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 Not Found errors', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/nonexistent',
        httpMethod: 'GET',
      };

      // Mock 404 response
      nock('https://api.example.com')
        .get('/nonexistent')
        .reply(404, { error: 'Not Found' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Not Found');
    });

    it('should handle 500 Internal Server errors', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/error',
        httpMethod: 'GET',
      };

      // Mock 500 response
      nock('https://api.example.com')
        .get('/error')
        .reply(500, { error: 'Internal Server Error' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('Internal Server Error');
    });

    it('should handle network errors gracefully', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://nonexistent-api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/test',
        httpMethod: 'GET',
      };

      // Mock network error (DNS failure)
      nock('https://nonexistent-api.example.com')
        .get('/test')
        .replyWithError({ code: 'ENOTFOUND', message: 'getaddrinfo ENOTFOUND' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(500);
      expect(response.body.error).toBeDefined();
    });

    it('should handle invalid JSON responses', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/invalid-json',
        httpMethod: 'GET',
      };

      // Mock invalid JSON response
      nock('https://api.example.com')
        .get('/invalid-json')
        .reply(200, 'invalid json response');

      // The client should handle JSON parsing errors
      const response = await apiClient.executeAPIRequest(connection, query);
      // Response should still be returned, but body parsing may fail
      expect(response.status).toBe(200);
    });
  });

  describe('Response Parsing', () => {
    it('should parse JSON response correctly', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/data',
        httpMethod: 'GET',
      };

      const mockData = {
        id: 1,
        name: 'Test',
        nested: {
          value: 'nested-value',
        },
      };

      nock('https://api.example.com')
        .get('/data')
        .reply(200, mockData);

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
      expect(response.body).toEqual(mockData);
      expect(response.body.nested.value).toBe('nested-value');
    });

    it('should include response headers', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/headers',
        httpMethod: 'GET',
      };

      nock('https://api.example.com')
        .get('/headers')
        .reply(200, { data: 'test' }, {
          'X-RateLimit-Remaining': '99',
          'X-Request-ID': 'req-123',
        });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
      expect(response.headers).toBeDefined();
      expect(response.headers['x-ratelimit-remaining']).toBe('99');
      expect(response.headers['x-request-id']).toBe('req-123');
    });

    it('should track execution time', async () => {
      const connection: APIConnection = {
        baseUrl: 'https://api.example.com',
      };

      const query: TestQuery = {
        name: 'test-query',
        apiEndpoint: '/slow',
        httpMethod: 'GET',
      };

      // Mock delayed response
      nock('https://api.example.com')
        .get('/slow')
        .delay(100)
        .reply(200, { data: 'slow response' });

      const response = await apiClient.executeAPIRequest(connection, query);
      expect(response.status).toBe(200);
      expect(response.executionTime).toBeGreaterThan(0);
      expect(response.executionTime).toBeLessThan(1000); // Should be reasonable
    });
  });
});
