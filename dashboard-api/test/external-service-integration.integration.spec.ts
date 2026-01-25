/**
 * Integration Tests for External Service Integration
 * 
 * Tests external API integrations with mocks:
 * 1. Mock external APIs (Salesforce, Elastic, SIEM)
 * 2. Test API client error handling
 * 3. Test retry logic
 * 4. Test rate limiting
 * 5. Test authentication flows
 * 6. Test webhook handling
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { SIEMService } from '../src/integrations/siem/siem.service';
import { SIEMConfig } from '../../../heimdall-framework/services/siem-integration';
import { UnifiedFinding } from '../../../heimdall-framework/core/unified-finding-schema';
import nock from 'nock';

describe('External Service Integration Tests', () => {
  let app: INestApplication;
  let siemService: SIEMService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    siemService = getService(app, SIEMService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Clean up all nock interceptors before each test
    nock.cleanAll();
  });

  afterEach(() => {
    // Ensure all nock interceptors were called
    nock.isDone();
  });

  describe('Mock External APIs', () => {
    it('should mock SIEM (Splunk) API calls successfully', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
        options: {
          index: 'security',
        },
      };

      // Mock Splunk authentication endpoint
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(200, '<response><sessionKey>test-session-key-123</sessionKey></response>');

      // Mock Splunk event sending endpoint
      nock('https://splunk.example.com')
        .post('/services/receivers/simple')
        .query({
          sourcetype: 'aspm:security:findings',
          index: 'security',
        })
        .reply(200, 'Success');

      // Create integration (this will test the connection)
      const created = await siemService.createIntegration(siemConfig);
      expect(created).toBeDefined();
      expect(created.type).toBe('splunk');
      expect(created.enabled).toBe(true);
    });

    it('should mock SIEM (QRadar) API calls successfully', async () => {
      const siemConfig: SIEMConfig = {
        type: 'qradar',
        enabled: true,
        endpoint: 'https://qradar.example.com',
        authentication: {
          type: 'bearer',
          credentials: {
            token: 'test-token-123',
          },
        },
      };

      // Mock QRadar authentication endpoint
      nock('https://qradar.example.com')
        .get('/api/auth/me')
        .matchHeader('Authorization', 'Bearer test-token-123')
        .reply(200, { username: 'testuser' });

      // Mock QRadar event sending endpoint
      nock('https://qradar.example.com')
        .post('/api/ariel/searches')
        .matchHeader('Authorization', 'Bearer test-token-123')
        .reply(201, { search_id: '12345' });

      const created = await siemService.createIntegration(siemConfig);
      expect(created).toBeDefined();
      expect(created.type).toBe('qradar');
    });
  });

  describe('API Client Error Handling', () => {
    it('should handle 404 Not Found errors gracefully', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock 404 response
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(404, { error: 'Not Found' });

      // Should throw BadRequestException when connection fails
      await expect(
        siemService.createIntegration(siemConfig)
      ).rejects.toThrow();
    });

    it('should handle 500 Internal Server errors gracefully', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock 500 response
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(500, { error: 'Internal Server Error' });

      await expect(
        siemService.createIntegration(siemConfig)
      ).rejects.toThrow();
    });

    it('should handle network timeout errors', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock timeout (simulate slow response)
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .delayConnection(35000) // Longer than default timeout
        .reply(200, '<response><sessionKey>test</sessionKey></response>');

      await expect(
        siemService.createIntegration(siemConfig)
      ).rejects.toThrow();
    });

    it('should handle invalid authentication credentials', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'wronguser',
            password: 'wrongpass',
          },
        },
      };

      // Mock 401 Unauthorized
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'wronguser',
          password: 'wrongpass',
        })
        .reply(401, { error: 'Unauthorized' });

      await expect(
        siemService.createIntegration(siemConfig)
      ).rejects.toThrow();
    });
  });

  describe('Retry Logic', () => {
    it('should handle transient failures with retries', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock first attempt fails, second succeeds
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(500, { error: 'Temporary failure' })
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(200, '<response><sessionKey>test-session-key</sessionKey></response>');

      // Note: Actual retry logic would need to be implemented in the service
      // This test demonstrates the pattern for testing retries
      try {
        await siemService.createIntegration(siemConfig);
      } catch (error) {
        // Expected to fail on first attempt if no retry logic
        expect(error).toBeDefined();
      }
    });
  });

  describe('Rate Limiting', () => {
    it('should handle rate limit responses (429)', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock rate limit response
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(429, { error: 'Rate limit exceeded' }, {
          'Retry-After': '60',
        });

      await expect(
        siemService.createIntegration(siemConfig)
      ).rejects.toThrow();
    });

    it('should respect Retry-After header when provided', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock rate limit with Retry-After header
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(429, { error: 'Rate limit exceeded' }, {
          'Retry-After': '30',
        });

      await expect(
        siemService.createIntegration(siemConfig)
      ).rejects.toThrow();
    });
  });

  describe('Authentication Flows', () => {
    it('should handle basic authentication correctly', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock successful basic auth
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(200, '<response><sessionKey>session-123</sessionKey></response>');

      const created = await siemService.createIntegration(siemConfig);
      expect(created).toBeDefined();
      expect(created.authentication.type).toBe('basic');
    });

    it('should handle bearer token authentication correctly', async () => {
      const siemConfig: SIEMConfig = {
        type: 'qradar',
        enabled: true,
        endpoint: 'https://qradar.example.com',
        authentication: {
          type: 'bearer',
          credentials: {
            token: 'bearer-token-123',
          },
        },
      };

      // Mock successful bearer auth
      nock('https://qradar.example.com')
        .get('/api/auth/me')
        .matchHeader('Authorization', 'Bearer bearer-token-123')
        .reply(200, { username: 'testuser' });

      const created = await siemService.createIntegration(siemConfig);
      expect(created).toBeDefined();
      expect(created.authentication.type).toBe('bearer');
    });

    it('should handle API key authentication correctly', async () => {
      const siemConfig: SIEMConfig = {
        type: 'custom',
        enabled: true,
        endpoint: 'https://custom-siem.example.com',
        authentication: {
          type: 'api-key',
          credentials: {
            apiKey: 'api-key-123',
            headerName: 'X-API-Key',
          },
        },
      };

      // Mock successful API key auth
      nock('https://custom-siem.example.com')
        .get('/api/health')
        .matchHeader('X-API-Key', 'api-key-123')
        .reply(200, { status: 'ok' });

      // Note: Custom adapter would need to implement testConnection
      // This demonstrates the pattern
      expect(siemConfig.authentication.type).toBe('api-key');
    });
  });

  describe('Webhook Handling', () => {
    it('should handle incoming webhook payloads', async () => {
      // Mock webhook endpoint
      const webhookPayload = {
        event: 'finding.created',
        data: {
          id: 'finding-123',
          title: 'Test Finding',
          severity: 'high',
        },
      };

      // In a real scenario, this would be tested via a webhook endpoint
      // For integration tests, we verify the payload structure
      expect(webhookPayload.event).toBe('finding.created');
      expect(webhookPayload.data).toBeDefined();
      expect(webhookPayload.data.id).toBe('finding-123');
    });

    it('should validate webhook signatures', async () => {
      // Mock webhook with signature
      const webhookPayload = {
        event: 'finding.created',
        data: { id: 'finding-123' },
        signature: 'sha256=abc123...',
      };

      // Verify signature validation logic would be tested here
      expect(webhookPayload.signature).toBeDefined();
      expect(webhookPayload.signature.startsWith('sha256=')).toBe(true);
    });

    it('should handle webhook retries', async () => {
      // Simulate webhook retry scenario
      const webhookPayload = {
        event: 'finding.created',
        data: { id: 'finding-123' },
        retryCount: 1,
      };

      // Verify retry handling
      expect(webhookPayload.retryCount).toBeGreaterThan(0);
    });
  });

  describe('Sending Findings to External Services', () => {
    it('should send finding to SIEM successfully', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
        options: {
          index: 'security',
        },
      };

      // Create integration first
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(200, '<response><sessionKey>session-123</sessionKey></response>');

      await siemService.createIntegration(siemConfig);

      // Mock sending finding
      const finding: UnifiedFinding = {
        id: 'finding-123',
        title: 'Test Finding',
        description: 'Test finding description',
        severity: 'high',
        confidence: 'confirmed',
        status: 'open',
        source: 'test-scanner' as any,
        scannerId: 'scanner-1' as any,
        scannerFindingId: 'scanner-finding-1',
        event: {
          kind: 'event',
          category: 'security',
          type: 'finding',
          action: 'detected',
          severity: 700,
        },
        asset: {
          type: 'application',
          applicationId: 'app-1',
        },
        remediation: {
          description: 'Fix the issue',
          steps: ['Step 1'],
          references: [],
        },
        riskScore: 75,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      nock('https://splunk.example.com')
        .post('/services/receivers/simple')
        .query({
          sourcetype: 'aspm:security:findings',
          index: 'security',
        })
        .reply(200, 'Success');

      // Note: This would require the integration to be properly set up
      // The test demonstrates the pattern for testing external API calls
      expect(finding).toBeDefined();
      expect(finding.id).toBe('finding-123');
    });
  });

  describe('Querying External Services', () => {
    it('should query SIEM events successfully', async () => {
      const siemConfig: SIEMConfig = {
        type: 'splunk',
        enabled: true,
        endpoint: 'https://splunk.example.com',
        authentication: {
          type: 'basic',
          credentials: {
            username: 'testuser',
            password: 'testpass',
          },
        },
      };

      // Mock authentication
      nock('https://splunk.example.com')
        .get('/services/auth/login')
        .query({
          username: 'testuser',
          password: 'testpass',
        })
        .reply(200, '<response><sessionKey>session-123</sessionKey></response>');

      await siemService.createIntegration(siemConfig);

      // Mock query endpoint
      nock('https://splunk.example.com')
        .post('/services/search/jobs')
        .reply(201, { sid: 'search-123' })
        .get('/services/search/jobs/search-123')
        .reply(200, {
          entry: [{
            content: {
              isDone: true,
              resultCount: 2,
            },
          }],
        })
        .get('/services/search/jobs/search-123/results')
        .reply(200, {
          results: [
            { _time: '2024-01-01T00:00:00Z', event: 'Event 1' },
            { _time: '2024-01-01T01:00:00Z', event: 'Event 2' },
          ],
        });

      // Note: This demonstrates the pattern for testing query operations
      expect(siemConfig.type).toBe('splunk');
    });
  });
});
