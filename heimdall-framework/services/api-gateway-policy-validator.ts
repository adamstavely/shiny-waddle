/**
 * API Gateway Policy Validator
 * 
 * Validates API gateway routing, authentication, rate limiting, and transformation policies
 */

export interface APIGatewayConfig {
  type: 'aws-api-gateway' | 'azure-api-management' | 'kong' | 'istio' | 'envoy';
  endpoint: string;
  policies: GatewayPolicy[];
  routes: Route[];
}

export interface GatewayPolicy {
  id: string;
  name: string;
  type: 'authentication' | 'authorization' | 'rate-limit' | 'transformation' | 'caching';
  config: any;
}

export interface Route {
  path: string;
  method: string;
  target: string;
  policies: string[]; // Policy IDs
}

export interface GatewayPolicyValidationResult {
  passed: boolean;
  gatewayType: string;
  policyIssues: PolicyIssue[];
  routingIssues: RoutingIssue[];
  authIssues: AuthIssue[];
}

export interface PolicyIssue {
  policyId: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  recommendation: string;
}

export interface RoutingIssue {
  route: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface AuthIssue {
  route: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface RoutingResult {
  route: Route;
  accessible: boolean;
  issues: string[];
}

export interface AuthResult {
  authenticated: boolean;
  authMethod?: string;
  issues: string[];
}

export interface RateLimitResult {
  configured: boolean;
  limit?: number;
  window?: number;
  issues: string[];
}

export interface TransformationResult {
  secure: boolean;
  transformations: string[];
  issues: string[];
}

export interface CachingResult {
  configured: boolean;
  cachePolicy?: string;
  issues: string[];
}

export class APIGatewayPolicyValidator {
  /**
   * Validate gateway policies
   */
  async validateGatewayPolicies(
    config: APIGatewayConfig
  ): Promise<GatewayPolicyValidationResult> {
    const policyIssues: PolicyIssue[] = [];
    const routingIssues: RoutingIssue[] = [];
    const authIssues: AuthIssue[] = [];

    // Validate each policy
    for (const policy of config.policies) {
      const issues = this.validatePolicy(policy, config.type);
      policyIssues.push(...issues);
    }

    // Validate routes
    for (const route of config.routes) {
      const routingIssuesForRoute = this.validateRoute(route, config);
      routingIssues.push(...routingIssuesForRoute);

      // Check authentication for route
      const authIssuesForRoute = this.validateRouteAuth(route, config);
      authIssues.push(...authIssuesForRoute);
    }

    const criticalIssues = [
      ...policyIssues.filter(i => i.severity === 'critical'),
      ...routingIssues.filter(i => i.severity === 'critical'),
      ...authIssues.filter(i => i.severity === 'critical'),
    ].length;

    return {
      passed: criticalIssues === 0,
      gatewayType: config.type,
      policyIssues,
      routingIssues,
      authIssues,
    };
  }

  /**
   * Test gateway routing
   */
  async testGatewayRouting(
    config: APIGatewayConfig,
    route: Route
  ): Promise<RoutingResult> {
    const issues: string[] = [];

    // Check if route has target
    if (!route.target) {
      issues.push('Route missing target');
    }

    // Check if route has policies
    if (!route.policies || route.policies.length === 0) {
      issues.push('Route has no policies applied');
    }

    // Check if route path is valid
    if (!route.path.startsWith('/')) {
      issues.push('Route path should start with /');
    }

    // Check for wildcard routes (security concern)
    if (route.path.includes('*') || route.path.includes('**')) {
      issues.push('Route contains wildcard - potential security risk');
    }

    return {
      route,
      accessible: issues.length === 0,
      issues,
    };
  }

  /**
   * Validate gateway authentication
   */
  async validateGatewayAuth(
    config: APIGatewayConfig
  ): Promise<AuthResult> {
    const issues: string[] = [];
    let authenticated = false;
    let authMethod: string | undefined;

    // Find authentication policies
    const authPolicies = config.policies.filter(p => p.type === 'authentication');

    if (authPolicies.length === 0) {
      issues.push('No authentication policies configured');
    } else {
      authenticated = true;
      authMethod = authPolicies[0].config?.method || 'unknown';

      // Validate auth method
      const secureMethods = ['jwt', 'oauth2', 'api-key', 'mutual-tls'];
      if (!secureMethods.includes(authMethod.toLowerCase())) {
        issues.push(`Authentication method ${authMethod} may not be secure`);
      }
    }

    // Check if all routes have authentication
    const routesWithoutAuth = config.routes.filter(
      route => !route.policies.some(policyId => {
        const policy = config.policies.find(p => p.id === policyId);
        return policy?.type === 'authentication';
      })
    );

    if (routesWithoutAuth.length > 0) {
      issues.push(`${routesWithoutAuth.length} routes without authentication`);
    }

    return {
      authenticated,
      authMethod,
      issues,
    };
  }

  /**
   * Test gateway rate limiting
   */
  async testGatewayRateLimiting(
    config: APIGatewayConfig
  ): Promise<RateLimitResult> {
    const issues: string[] = [];

    // Find rate limiting policies
    const rateLimitPolicies = config.policies.filter(p => p.type === 'rate-limit');

    if (rateLimitPolicies.length === 0) {
      issues.push('No rate limiting policies configured');
      return {
        configured: false,
        issues,
      };
    }

    const policy = rateLimitPolicies[0];
    const limit = policy.config?.limit;
    const window = policy.config?.window;

    if (!limit) {
      issues.push('Rate limit policy missing limit value');
    }

    if (!window) {
      issues.push('Rate limit policy missing window value');
    }

    // Check if rate limit is reasonable
    if (limit && limit > 10000) {
      issues.push('Rate limit is very high - may not provide protection');
    }

    return {
      configured: true,
      limit,
      window,
      issues,
    };
  }

  /**
   * Validate gateway transformation
   */
  async validateGatewayTransformation(
    config: APIGatewayConfig
  ): Promise<TransformationResult> {
    const issues: string[] = [];
    const transformations: string[] = [];

    // Find transformation policies
    const transformPolicies = config.policies.filter(p => p.type === 'transformation');

    for (const policy of transformPolicies) {
      const transformType = policy.config?.type || 'unknown';
      transformations.push(transformType);

      // Check for security concerns in transformations
      if (transformType === 'header-injection' || transformType === 'query-injection') {
        issues.push(`Transformation type ${transformType} may be insecure`);
      }

      // Check if transformation modifies sensitive headers
      if (policy.config?.modifiesHeaders) {
        const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];
        const modifiedHeaders = policy.config.modifiedHeaders || [];
        const hasSensitive = modifiedHeaders.some((h: string) =>
          sensitiveHeaders.includes(h.toLowerCase())
        );

        if (hasSensitive) {
          issues.push('Transformation modifies sensitive headers');
        }
      }
    }

    return {
      secure: issues.length === 0,
      transformations,
      issues,
    };
  }

  /**
   * Test gateway caching
   */
  async testGatewayCaching(
    config: APIGatewayConfig
  ): Promise<CachingResult> {
    const issues: string[] = [];

    // Find caching policies
    const cachePolicies = config.policies.filter(p => p.type === 'caching');

    if (cachePolicies.length === 0) {
      return {
        configured: false,
        issues: ['No caching policies configured'],
      };
    }

    const policy = cachePolicies[0];
    const cachePolicy = policy.config?.policy || 'default';

    // Check if caching is enabled for sensitive endpoints
    const sensitiveRoutes = config.routes.filter(
      route => route.path.includes('/auth') || route.path.includes('/token')
    );

    const cachedSensitiveRoutes = sensitiveRoutes.filter(route =>
      route.policies.includes(policy.id)
    );

    if (cachedSensitiveRoutes.length > 0) {
      issues.push('Caching enabled for sensitive endpoints');
    }

    return {
      configured: true,
      cachePolicy,
      issues,
    };
  }

  /**
   * Validate a single policy
   */
  private validatePolicy(
    policy: GatewayPolicy,
    gatewayType: string
  ): PolicyIssue[] {
    const issues: PolicyIssue[] = [];

    // Check policy structure
    if (!policy.id) {
      issues.push({
        policyId: 'unknown',
        issue: 'Policy missing ID',
        severity: 'high',
        recommendation: 'All policies must have a unique ID',
      });
    }

    if (!policy.config) {
      issues.push({
        policyId: policy.id || 'unknown',
        issue: 'Policy missing configuration',
        severity: 'high',
        recommendation: 'Policies must have configuration',
      });
    }

    // Type-specific validation
    switch (policy.type) {
      case 'authentication':
        if (!policy.config?.method) {
          issues.push({
            policyId: policy.id || 'unknown',
            issue: 'Authentication policy missing method',
            severity: 'critical',
            recommendation: 'Specify authentication method',
          });
        }
        break;

      case 'rate-limit':
        if (!policy.config?.limit) {
          issues.push({
            policyId: policy.id || 'unknown',
            issue: 'Rate limit policy missing limit',
            severity: 'high',
            recommendation: 'Specify rate limit value',
          });
        }
        break;
    }

    return issues;
  }

  /**
   * Validate a route
   */
  private validateRoute(
    route: Route,
    config: APIGatewayConfig
  ): RoutingIssue[] {
    const issues: RoutingIssue[] = [];

    if (!route.target) {
      issues.push({
        route: route.path,
        issue: 'Route missing target',
        severity: 'critical',
      });
    }

    if (!route.policies || route.policies.length === 0) {
      issues.push({
        route: route.path,
        issue: 'Route has no policies',
        severity: 'high',
      });
    }

    // Check if route uses HTTP methods
    const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
    if (!validMethods.includes(route.method.toUpperCase())) {
      issues.push({
        route: route.path,
        issue: `Invalid HTTP method: ${route.method}`,
        severity: 'medium',
      });
    }

    return issues;
  }

  /**
   * Validate route authentication
   */
  private validateRouteAuth(
    route: Route,
    config: APIGatewayConfig
  ): AuthIssue[] {
    const issues: AuthIssue[] = [];

    // Check if route has authentication policy
    const hasAuth = route.policies.some(policyId => {
      const policy = config.policies.find(p => p.id === policyId);
      return policy?.type === 'authentication';
    });

    // Public endpoints might not need auth, but sensitive ones should
    const sensitivePaths = ['/admin', '/api/v1/users', '/api/v1/data'];
    const isSensitive = sensitivePaths.some(path => route.path.includes(path));

    if (isSensitive && !hasAuth) {
      issues.push({
        route: route.path,
        issue: 'Sensitive route missing authentication',
        severity: 'critical',
      });
    }

    return issues;
  }
}

