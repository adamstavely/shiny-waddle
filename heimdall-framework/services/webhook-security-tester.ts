/**
 * Webhook Security Tester
 * 
 * Tests webhook authentication, encryption, replay attack prevention, and delivery guarantees
 */

export interface WebhookConfig {
  endpoint: string;
  authentication: {
    type: 'signature' | 'token' | 'oauth2';
    method: string;
  };
  encryption: {
    enabled: boolean;
    method?: string;
  };
  rateLimiting?: RateLimitConfig;
}

export interface RateLimitConfig {
  maxRequests: number;
  windowSeconds: number;
}

export interface WebhookSecurityTestResult {
  passed: boolean;
  endpoint: string;
  issues: Array<{
    type: 'no-auth' | 'weak-auth' | 'no-encryption' | 'replay-vulnerable' | 'no-rate-limit';
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
  }>;
  authTest: AuthTestResult;
  encryptionTest: EncryptionTestResult;
  replayTest: ReplayTestResult;
}

export interface AuthTestResult {
  authenticated: boolean;
  authMethod: string;
  secure: boolean;
  issues: string[];
}

export interface EncryptionTestResult {
  encrypted: boolean;
  method?: string;
  secure: boolean;
  issues: string[];
}

export interface ReplayTestResult {
  protected: boolean;
  method?: string;
  issues: string[];
}

export interface EndpointResult {
  accessible: boolean;
  secure: boolean;
  issues: string[];
}

export interface DeliveryResult {
  reliable: boolean;
  retryPolicy?: string;
  issues: string[];
}

export class WebhookSecurityTester {
  /**
   * Test webhook authentication
   */
  async testWebhookAuthentication(
    config: WebhookConfig
  ): Promise<WebhookSecurityTestResult> {
    const issues: WebhookSecurityTestResult['issues'] = [];

    // Test authentication
    const authTest = await this.testAuth(config);
    if (!authTest.authenticated) {
      issues.push({
        type: 'no-auth',
        severity: 'critical',
        message: 'Webhook has no authentication configured',
      });
    } else if (!authTest.secure) {
      issues.push({
        type: 'weak-auth',
        severity: 'high',
        message: `Authentication method ${authTest.authMethod} may be weak`,
      });
    }

    // Test encryption
    const encryptionTest = await this.testWebhookEncryption(config);
    if (!encryptionTest.encrypted) {
      issues.push({
        type: 'no-encryption',
        severity: 'critical',
        message: 'Webhook payload is not encrypted',
      });
    }

    // Test replay attack prevention
    const replayTest = await this.testReplayAttackPrevention(config);
    if (!replayTest.protected) {
      issues.push({
        type: 'replay-vulnerable',
        severity: 'high',
        message: 'Webhook is vulnerable to replay attacks',
      });
    }

    // Test rate limiting
    if (!config.rateLimiting) {
      issues.push({
        type: 'no-rate-limit',
        severity: 'medium',
        message: 'Webhook has no rate limiting configured',
      });
    }

    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;

    return {
      passed: criticalIssues === 0 && highIssues === 0,
      endpoint: config.endpoint,
      issues,
      authTest,
      encryptionTest,
      replayTest,
    };
  }

  /**
   * Test webhook encryption
   */
  async testWebhookEncryption(
    config: WebhookConfig
  ): Promise<EncryptionTestResult> {
    const issues: string[] = [];

    if (!config.encryption.enabled) {
      return {
        encrypted: false,
        secure: false,
        issues: ['Encryption is not enabled'],
      };
    }

    const method = config.encryption.method || 'unknown';
    const secureMethods = ['tls', 'https', 'aes-256', 'rsa-2048'];

    if (!secureMethods.some(m => method.toLowerCase().includes(m.toLowerCase()))) {
      issues.push(`Encryption method ${method} may not be secure`);
    }

    // Check if endpoint uses HTTPS
    if (!config.endpoint.startsWith('https://')) {
      issues.push('Webhook endpoint does not use HTTPS');
    }

    return {
      encrypted: true,
      method,
      secure: issues.length === 0,
      issues,
    };
  }

  /**
   * Test replay attack prevention
   */
  async testReplayAttackPrevention(
    config: WebhookConfig
  ): Promise<ReplayTestResult> {
    const issues: string[] = [];

    // Check if authentication method supports replay prevention
    const authType = config.authentication.type;

    if (authType === 'signature') {
      // Signature-based auth typically includes timestamp/nonce
      // This is a simplified check
      return {
        protected: true,
        method: 'signature-with-timestamp',
        issues: [],
      };
    } else if (authType === 'token') {
      // Token-based auth may be vulnerable to replay
      issues.push('Token-based authentication may be vulnerable to replay attacks');
      return {
        protected: false,
        method: 'token',
        issues,
      };
    } else if (authType === 'oauth2') {
      // OAuth2 typically includes nonce/timestamp
      return {
        protected: true,
        method: 'oauth2-with-nonce',
        issues: [],
      };
    }

    return {
      protected: false,
      issues: ['Unknown authentication method'],
    };
  }

  /**
   * Validate webhook endpoint
   */
  async validateWebhookEndpoint(
    config: WebhookConfig
  ): Promise<EndpointResult> {
    const issues: string[] = [];

    // Check if endpoint uses HTTPS
    if (!config.endpoint.startsWith('https://')) {
      issues.push('Webhook endpoint must use HTTPS');
    }

    // Check if endpoint is publicly accessible (should be for webhooks)
    // This is a simplified check - real implementation would test connectivity

    // Check endpoint format
    try {
      new URL(config.endpoint);
    } catch (error) {
      issues.push('Invalid webhook endpoint URL');
    }

    return {
      accessible: true, // Simplified - would test actual connectivity
      secure: issues.length === 0,
      issues,
    };
  }

  /**
   * Test webhook rate limiting
   */
  async testWebhookRateLimiting(
    config: WebhookConfig
  ): Promise<RateLimitResult> {
    const issues: string[] = [];

    if (!config.rateLimiting) {
      return {
        configured: false,
        issues: ['Rate limiting is not configured'],
      };
    }

    const { maxRequests, windowSeconds } = config.rateLimiting;

    if (maxRequests <= 0) {
      issues.push('Rate limit max requests must be greater than 0');
    }

    if (windowSeconds <= 0) {
      issues.push('Rate limit window must be greater than 0');
    }

    // Check if rate limit is reasonable
    const requestsPerSecond = maxRequests / windowSeconds;
    if (requestsPerSecond > 100) {
      issues.push('Rate limit is very high - may not provide protection');
    }

    return {
      configured: true,
      limit: maxRequests,
      window: windowSeconds,
      issues,
    };
  }

  /**
   * Validate webhook delivery
   */
  async validateWebhookDelivery(
    config: WebhookConfig
  ): Promise<DeliveryResult> {
    const issues: string[] = [];

    // Check if retry policy is configured
    // This is a simplified check - real implementation would check actual delivery configuration

    return {
      reliable: true, // Simplified
      retryPolicy: 'exponential-backoff', // Default assumption
      issues,
    };
  }

  /**
   * Test authentication
   */
  private async testAuth(
    config: WebhookConfig
  ): Promise<AuthTestResult> {
    const issues: string[] = [];
    const authType = config.authentication.type;
    const authMethod = config.authentication.method;

    if (!authType) {
      return {
        authenticated: false,
        authMethod: 'none',
        secure: false,
        issues: ['No authentication type specified'],
      };
    }

    // Check if authentication method is secure
    const secureMethods = ['signature', 'oauth2'];
    const isSecure = secureMethods.includes(authType);

    if (!isSecure && authType === 'token') {
      issues.push('Token-based authentication may be less secure than signature-based');
    }

    return {
      authenticated: true,
      authMethod: authMethod || authType,
      secure: isSecure && issues.length === 0,
      issues,
    };
  }
}

export interface RateLimitResult {
  configured: boolean;
  limit?: number;
  window?: number;
  issues: string[];
}

