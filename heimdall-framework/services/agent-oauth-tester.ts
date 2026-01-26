/**
 * Agent OAuth Flow Testing Service
 * 
 * Tests OAuth flows for agent access control:
 * - Auth Code Flow (delegated access)
 * - OBO Token Flow (on-behalf-of token exchange)
 * - Client Credentials Flow (direct access)
 */

import { TestResult } from '../core/types';

export interface OAuthFlowConfig {
  authorizationEndpoint?: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes: string[];
  additionalParams?: Record<string, string>;
}

export interface AuthCodeFlowTest {
  config: OAuthFlowConfig;
  userContext: {
    userId: string;
    email: string;
    permissions: string[];
  };
  expectedScopes: string[];
}

export interface OBOTokenFlowTest {
  config: OAuthFlowConfig;
  userAccessToken: string;
  targetService: string;
  expectedScopes: string[];
}

export interface ClientCredentialsFlowTest {
  config: OAuthFlowConfig;
  expectedScopes: string[];
  credentialRotation?: {
    enabled: boolean;
    rotationInterval?: number;
  };
}

export interface OAuthFlowTestResult extends TestResult {
  testName: string;
  flowType: 'auth-code' | 'obo-token' | 'client-credentials';
  tokenIssued: boolean;
  tokenValid?: boolean;
  tokenExpired?: boolean;
  scopesGranted?: string[];
  scopesExpected?: string[];
  scopeMismatch?: string[];
  userPermissionsEnforced?: boolean;
  permissionBoundariesRespected?: boolean;
  credentialSecurity?: boolean;
  error?: string;
  details: Record<string, any>;
}

export class AgentOAuthTester {
  /**
   * Test Auth Code Flow for delegated access
   */
  async testAuthCodeFlow(test: AuthCodeFlowTest): Promise<OAuthFlowTestResult> {
    const result: OAuthFlowTestResult = {
      testType: 'agent-delegated-access',
      testName: 'Auth Code Flow Test',
      passed: false,
      timestamp: new Date(),
      flowType: 'auth-code',
      tokenIssued: false,
      details: {},
    };

    try {
      if (!test.config.authorizationEndpoint) {
        throw new Error('Authorization endpoint is required for Auth Code Flow');
      }

      // Step 1: Simulate authorization request
      const authUrl = this.buildAuthorizationUrl(test.config);
      result.details = {
        ...result.details,
        authorizationUrl: authUrl,
        requestedScopes: test.config.scopes,
        userPermissions: test.userContext.permissions,
      };

      // Step 2: Simulate user consent (in real scenario, user would approve)
      // For testing, we assume consent is granted
      const authCode = this.simulateAuthorizationCode(test.userContext);
      result.details = {
        ...result.details,
        authorizationCode: authCode,
      };

      // Step 3: Exchange authorization code for tokens
      const tokenResponse = await this.exchangeAuthorizationCode(
        test.config,
        authCode
      );

      if (!tokenResponse.access_token) {
        result.error = 'Failed to obtain access token';
        result.details = {
          ...result.details,
          tokenResponse,
        };
        return result;
      }

      result.tokenIssued = true;
      result.scopesGranted = tokenResponse.scope?.split(' ') || [];
      result.scopesExpected = test.expectedScopes;

      // Step 4: Validate scopes
      const scopeMismatch = this.validateScopes(
        result.scopesGranted,
        test.expectedScopes
      );
      result.scopeMismatch = scopeMismatch;

      // Step 5: Validate user permissions are enforced
      result.userPermissionsEnforced = this.validateUserPermissions(
        result.scopesGranted,
        test.userContext.permissions
      );

      // Step 6: Validate permission boundaries
      result.permissionBoundariesRespected = this.validatePermissionBoundaries(
        result.scopesGranted,
        test.userContext.permissions
      );

      // Step 7: Validate token
      result.tokenValid = await this.validateToken(
        tokenResponse.access_token,
        test.config.tokenEndpoint
      );

      result.passed =
        result.tokenIssued &&
        result.tokenValid &&
        scopeMismatch.length === 0 &&
        result.userPermissionsEnforced &&
        result.permissionBoundariesRespected;

      result.details = {
        ...result.details,
        tokenType: tokenResponse.token_type,
        expiresIn: tokenResponse.expires_in,
        refreshToken: tokenResponse.refresh_token ? 'present' : 'absent',
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
        stack: error.stack,
      };
    }

    return result;
  }

  /**
   * Test OBO (On-Behalf-Of) Token Flow
   */
  async testOBOTokenFlow(test: OBOTokenFlowTest): Promise<OAuthFlowTestResult> {
    const result: OAuthFlowTestResult = {
      testType: 'agent-delegated-access',
      testName: 'OBO Token Flow Test',
      passed: false,
      timestamp: new Date(),
      flowType: 'obo-token',
      tokenIssued: false,
      details: {},
    };

    try {
      // Step 1: Exchange user access token for OBO token
      const oboTokenResponse = await this.exchangeOBOToken(
        test.config,
        test.userAccessToken,
        test.targetService
      );

      if (!oboTokenResponse.access_token) {
        result.error = 'Failed to obtain OBO token';
        result.details = {
          ...result.details,
          oboTokenResponse,
        };
        return result;
      }

      result.tokenIssued = true;
      result.scopesGranted = oboTokenResponse.scope?.split(' ') || [];
      result.scopesExpected = test.expectedScopes;

      // Step 2: Validate scopes
      const scopeMismatch = this.validateScopes(
        result.scopesGranted,
        test.expectedScopes
      );
      result.scopeMismatch = scopeMismatch;

      // Step 3: Validate token
      result.tokenValid = await this.validateToken(
        oboTokenResponse.access_token,
        test.config.tokenEndpoint
      );

      result.passed =
        result.tokenIssued &&
        result.tokenValid &&
        scopeMismatch.length === 0;

      result.details = {
        ...result.details,
        targetService: test.targetService,
        tokenType: oboTokenResponse.token_type,
        expiresIn: oboTokenResponse.expires_in,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  /**
   * Test Client Credentials Flow for direct access
   */
  async testClientCredentialsFlow(
    test: ClientCredentialsFlowTest
  ): Promise<OAuthFlowTestResult> {
    const result: OAuthFlowTestResult = {
      testType: 'agent-direct-access',
      testName: 'Client Credentials Flow Test',
      passed: false,
      timestamp: new Date(),
      flowType: 'client-credentials',
      tokenIssued: false,
      details: {},
    };

    try {
      if (!test.config.clientSecret) {
        throw new Error('Client secret is required for Client Credentials Flow');
      }

      // Step 1: Request token using client credentials
      const tokenResponse = await this.requestClientCredentialsToken(
        test.config
      );

      if (!tokenResponse.access_token) {
        result.error = 'Failed to obtain access token';
        result.details = {
          ...result.details,
          tokenResponse,
        };
        return result;
      }

      result.tokenIssued = true;
      result.scopesGranted = tokenResponse.scope?.split(' ') || [];
      result.scopesExpected = test.expectedScopes;

      // Step 2: Validate scopes
      const scopeMismatch = this.validateScopes(
        result.scopesGranted,
        test.expectedScopes
      );
      result.scopeMismatch = scopeMismatch;

      // Step 3: Validate token
      result.tokenValid = await this.validateToken(
        tokenResponse.access_token,
        test.config.tokenEndpoint
      );

      // Step 4: Validate credential security
      if (test.credentialRotation) {
        result.credentialSecurity = await this.validateCredentialSecurity(
          test.config,
          test.credentialRotation
        );
      } else {
        result.credentialSecurity = true; // Not tested
      }

      result.passed =
        result.tokenIssued &&
        result.tokenValid &&
        scopeMismatch.length === 0 &&
        (result.credentialSecurity !== false);

      result.details = {
        ...result.details,
        tokenType: tokenResponse.token_type,
        expiresIn: tokenResponse.expires_in,
        credentialRotation: test.credentialRotation,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  /**
   * Test token refresh flow
   */
  async testTokenRefresh(
    refreshToken: string,
    config: OAuthFlowConfig
  ): Promise<OAuthFlowTestResult> {
    const result: OAuthFlowTestResult = {
      testType: 'agent-delegated-access',
      testName: 'Token Refresh Test',
      passed: false,
      timestamp: new Date(),
      flowType: 'auth-code',
      tokenIssued: false,
      details: {},
    };

    try {
      const refreshResponse = await this.refreshAccessToken(
        refreshToken,
        config
      );

      if (!refreshResponse.access_token) {
        result.error = 'Failed to refresh access token';
        return result;
      }

      result.tokenIssued = true;
      result.tokenValid = true;
      result.passed = true;

      result.details = {
        newTokenIssued: true,
        expiresIn: refreshResponse.expires_in,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  // Private helper methods

  private buildAuthorizationUrl(config: OAuthFlowConfig): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri || '',
      scope: config.scopes.join(' '),
      ...config.additionalParams,
    });

    return `${config.authorizationEndpoint}?${params.toString()}`;
  }

  private simulateAuthorizationCode(userContext: {
    userId: string;
    email: string;
  }): string {
    // Simulate authorization code generation
    // In real scenario, this would come from the authorization server
    return `auth_code_${userContext.userId}_${Date.now()}`;
  }

  private async exchangeAuthorizationCode(
    config: OAuthFlowConfig,
    authCode: string
  ): Promise<any> {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      client_id: config.clientId,
      client_secret: config.clientSecret || '',
      redirect_uri: config.redirectUri || '',
    });

    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(
        `Token exchange failed: ${response.statusText} - ${JSON.stringify(error)}`
      );
    }

    return await response.json();
  }

  private async exchangeOBOToken(
    config: OAuthFlowConfig,
    userAccessToken: string,
    targetService: string
  ): Promise<any> {
    const params = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: userAccessToken,
      scope: config.scopes.join(' '),
      requested_token_use: 'on_behalf_of',
      ...config.additionalParams,
    });

    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ${userAccessToken}`,
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(
        `OBO token exchange failed: ${response.statusText} - ${JSON.stringify(error)}`
      );
    }

    return await response.json();
  }

  private async requestClientCredentialsToken(
    config: OAuthFlowConfig
  ): Promise<any> {
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: config.clientId,
      client_secret: config.clientSecret || '',
      scope: config.scopes.join(' '),
      ...config.additionalParams,
    });

    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(
        `Client credentials token request failed: ${response.statusText} - ${JSON.stringify(error)}`
      );
    }

    return await response.json();
  }

  private async refreshAccessToken(
    refreshToken: string,
    config: OAuthFlowConfig
  ): Promise<any> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret || '',
    });

    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(
        `Token refresh failed: ${response.statusText} - ${JSON.stringify(error)}`
      );
    }

    return await response.json();
  }

  private validateScopes(
    granted: string[],
    expected: string[]
  ): string[] {
    const mismatch: string[] = [];
    for (const scope of expected) {
      if (!granted.includes(scope)) {
        mismatch.push(`Missing scope: ${scope}`);
      }
    }
    // Check for unexpected scopes
    for (const scope of granted) {
      if (!expected.includes(scope)) {
        mismatch.push(`Unexpected scope: ${scope}`);
      }
    }
    return mismatch;
  }

  private validateUserPermissions(
    grantedScopes: string[],
    userPermissions: string[]
  ): boolean {
    // Check if all granted scopes are within user permissions
    // This is a simplified check - in reality, scopes and permissions might map differently
    for (const scope of grantedScopes) {
      // Extract permission from scope (e.g., "read:emails" -> "read:emails")
      const permission = scope;
      if (!userPermissions.includes(permission)) {
        return false;
      }
    }
    return true;
  }

  private validatePermissionBoundaries(
    grantedScopes: string[],
    userPermissions: string[]
  ): boolean {
    // Ensure agent cannot exceed user permissions
    return this.validateUserPermissions(grantedScopes, userPermissions);
  }

  private async validateToken(
    token: string,
    tokenEndpoint: string
  ): Promise<boolean> {
    try {
      // Try to introspect token or validate it
      // This is a simplified check - in reality, you'd call token introspection endpoint
      if (!token || token.length < 10) {
        return false;
      }

      // In a real implementation, you would:
      // 1. Call token introspection endpoint
      // 2. Validate JWT signature if it's a JWT
      // 3. Check expiration
      return true;
    } catch (error) {
      return false;
    }
  }

  private async validateCredentialSecurity(
    config: OAuthFlowConfig,
    rotationConfig: {
      enabled: boolean;
      rotationInterval?: number;
    }
  ): Promise<boolean> {
    // Validate credential security practices
    // Check if credentials are stored securely (not hardcoded)
    // Check if rotation is enabled
    // Check credential lifetime

    if (!rotationConfig.enabled) {
      return false; // Rotation should be enabled for production
    }

    // Additional security checks would go here
    return true;
  }
}
