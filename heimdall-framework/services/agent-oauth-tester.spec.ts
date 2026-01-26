/**
 * Agent OAuth Tester Unit Tests
 */

import { AgentOAuthTester, AuthCodeFlowTest, OBOTokenFlowTest, ClientCredentialsFlowTest } from './agent-oauth-tester';

// Mock fetch globally
global.fetch = jest.fn();

describe('AgentOAuthTester', () => {
  let tester: AgentOAuthTester;

  beforeEach(() => {
    tester = new AgentOAuthTester();
    jest.clearAllMocks();
  });

  describe('testAuthCodeFlow', () => {
    it('should successfully test Auth Code Flow', async () => {
      const test: AuthCodeFlowTest = {
        config: {
          authorizationEndpoint: 'https://auth.example.com/authorize',
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          redirectUri: 'https://app.example.com/callback',
          scopes: ['read:emails'],
        },
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          permissions: ['read:emails'],
        },
        expectedScopes: ['read:emails'],
      };

      // Mock token endpoint response
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'test-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'test-refresh-token',
          scope: 'read:emails',
        }),
      });

      const result = await tester.testAuthCodeFlow(test);

      expect(result.passed).toBe(true);
      expect(result.tokenIssued).toBe(true);
      expect(result.tokenValid).toBe(true);
      expect(result.scopesGranted).toEqual(['read:emails']);
      expect(result.userPermissionsEnforced).toBe(true);
      expect(result.permissionBoundariesRespected).toBe(true);
    });

    it('should fail when authorization endpoint is missing', async () => {
      const test: AuthCodeFlowTest = {
        config: {
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          redirectUri: 'https://app.example.com/callback',
          scopes: ['read:emails'],
        },
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          permissions: ['read:emails'],
        },
        expectedScopes: ['read:emails'],
      };

      const result = await tester.testAuthCodeFlow(test);

      expect(result.passed).toBe(false);
      expect(result.error).toContain('Authorization endpoint is required');
    });

    it('should detect scope mismatches', async () => {
      const test: AuthCodeFlowTest = {
        config: {
          authorizationEndpoint: 'https://auth.example.com/authorize',
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          redirectUri: 'https://app.example.com/callback',
          scopes: ['read:emails', 'write:emails'],
        },
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          permissions: ['read:emails'],
        },
        expectedScopes: ['read:emails'],
      };

      // Mock token endpoint response with unexpected scope
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'test-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'read:emails write:emails',
        }),
      });

      const result = await tester.testAuthCodeFlow(test);

      expect(result.passed).toBe(false);
      expect(result.scopeMismatch).toContain('Unexpected scope: write:emails');
    });

    it('should detect permission boundary violations', async () => {
      const test: AuthCodeFlowTest = {
        config: {
          authorizationEndpoint: 'https://auth.example.com/authorize',
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          redirectUri: 'https://app.example.com/callback',
          scopes: ['read:emails', 'delete:emails'],
        },
        userContext: {
          userId: 'user-123',
          email: 'user@example.com',
          permissions: ['read:emails'], // User doesn't have delete permission
        },
        expectedScopes: ['read:emails', 'delete:emails'],
      };

      // Mock token endpoint response
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'test-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'read:emails delete:emails',
        }),
      });

      const result = await tester.testAuthCodeFlow(test);

      expect(result.passed).toBe(false);
      expect(result.userPermissionsEnforced).toBe(false);
    });
  });

  describe('testOBOTokenFlow', () => {
    it('should successfully test OBO Token Flow', async () => {
      const test: OBOTokenFlowTest = {
        config: {
          tokenEndpoint: 'https://service.example.com/token',
          clientId: 'test-client',
          scopes: ['read:documents'],
        },
        userAccessToken: 'user-access-token',
        targetService: 'document-service',
        expectedScopes: ['read:documents'],
      };

      // Mock OBO token endpoint response
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'obo-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'read:documents',
        }),
      });

      const result = await tester.testOBOTokenFlow(test);

      expect(result.passed).toBe(true);
      expect(result.tokenIssued).toBe(true);
      expect(result.tokenValid).toBe(true);
      expect(result.scopesGranted).toEqual(['read:documents']);
    });

    it('should handle OBO token exchange failures', async () => {
      const test: OBOTokenFlowTest = {
        config: {
          tokenEndpoint: 'https://service.example.com/token',
          clientId: 'test-client',
          scopes: ['read:documents'],
        },
        userAccessToken: 'invalid-token',
        targetService: 'document-service',
        expectedScopes: ['read:documents'],
      };

      // Mock failed token exchange
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        statusText: 'Unauthorized',
        json: async () => ({ error: 'invalid_token' }),
      });

      const result = await tester.testOBOTokenFlow(test);

      expect(result.passed).toBe(false);
      expect(result.error).toContain('OBO token exchange failed');
    });
  });

  describe('testClientCredentialsFlow', () => {
    it('should successfully test Client Credentials Flow', async () => {
      const test: ClientCredentialsFlowTest = {
        config: {
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          clientSecret: 'test-secret',
          scopes: ['read:logs'],
        },
        expectedScopes: ['read:logs'],
        credentialRotation: {
          enabled: true,
          rotationInterval: 90 * 24 * 60 * 60,
        },
      };

      // Mock token endpoint response
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'client-credentials-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'read:logs',
        }),
      });

      const result = await tester.testClientCredentialsFlow(test);

      expect(result.passed).toBe(true);
      expect(result.tokenIssued).toBe(true);
      expect(result.tokenValid).toBe(true);
      expect(result.scopesGranted).toEqual(['read:logs']);
      expect(result.credentialSecurity).toBe(true);
    });

    it('should fail when client secret is missing', async () => {
      const test: ClientCredentialsFlowTest = {
        config: {
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          scopes: ['read:logs'],
        },
        expectedScopes: ['read:logs'],
      };

      const result = await tester.testClientCredentialsFlow(test);

      expect(result.passed).toBe(false);
      expect(result.error).toContain('Client secret is required');
    });

    it('should detect when credential rotation is disabled', async () => {
      const test: ClientCredentialsFlowTest = {
        config: {
          tokenEndpoint: 'https://auth.example.com/token',
          clientId: 'test-client',
          clientSecret: 'test-secret',
          scopes: ['read:logs'],
        },
        expectedScopes: ['read:logs'],
        credentialRotation: {
          enabled: false,
        },
      };

      // Mock token endpoint response
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'client-credentials-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'read:logs',
        }),
      });

      const result = await tester.testClientCredentialsFlow(test);

      expect(result.passed).toBe(false);
      expect(result.credentialSecurity).toBe(false);
    });
  });

  describe('testTokenRefresh', () => {
    it('should successfully refresh access token', async () => {
      const refreshToken = 'refresh-token-123';
      const config = {
        tokenEndpoint: 'https://auth.example.com/token',
        clientId: 'test-client',
        clientSecret: 'test-secret',
        scopes: ['read:emails'],
      };

      // Mock refresh token endpoint response
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'new-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      const result = await tester.testTokenRefresh(refreshToken, config);

      expect(result.passed).toBe(true);
      expect(result.tokenIssued).toBe(true);
      expect(result.tokenValid).toBe(true);
    });

    it('should handle refresh token failures', async () => {
      const refreshToken = 'invalid-refresh-token';
      const config = {
        tokenEndpoint: 'https://auth.example.com/token',
        clientId: 'test-client',
        clientSecret: 'test-secret',
        scopes: ['read:emails'],
      };

      // Mock failed refresh
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        statusText: 'Bad Request',
        json: async () => ({ error: 'invalid_grant' }),
      });

      const result = await tester.testTokenRefresh(refreshToken, config);

      expect(result.passed).toBe(false);
      expect(result.error).toContain('Failed to refresh access token');
    });
  });
});
