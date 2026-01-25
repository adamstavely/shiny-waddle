export enum APITestType {
  REST = 'rest',
  GRAPHQL = 'graphql',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  RATE_LIMITING = 'rate-limiting',
  VULNERABILITY = 'vulnerability',
}

export enum HTTPMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
  PATCH = 'PATCH',
  OPTIONS = 'OPTIONS',
}

export enum AuthenticationType {
  BEARER = 'bearer',
  BASIC = 'basic',
  OAUTH2 = 'oauth2',
  API_KEY = 'api-key',
  JWT = 'jwt',
}

export interface APISecurityTestConfigEntity {
  id: string;
  name: string;
  baseUrl: string;
  authentication?: {
    type: AuthenticationType | string;
    credentials: Record<string, string>;
  };
  rateLimitConfig?: {
    maxRequests?: number;
    windowSeconds?: number;
    strategy?: 'fixed' | 'sliding' | 'token-bucket';
  };
  headers?: Record<string, string>;
  timeout?: number;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface APIEndpointEntity {
  id: string;
  configId: string;
  name: string;
  endpoint: string;
  method: HTTPMethod | string;
  apiType: APITestType | string;
  expectedStatus?: number;
  expectedAuthRequired?: boolean;
  expectedRateLimit?: boolean;
  body?: any;
  headers?: Record<string, string>;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface APISecurityTestResultEntity {
  id: string;
  configId: string;
  endpointId?: string;
  testName: string;
  endpoint: string;
  method: HTTPMethod | string;
  testType: APITestType | string;
  status: 'passed' | 'failed' | 'warning';
  statusCode?: number;
  responseTime?: number;
  rateLimitInfo?: {
    limit?: number;
    remaining?: number;
    resetTime?: Date | string;
  };
  authenticationResult?: {
    authenticated: boolean;
    tokenValid?: boolean;
    tokenExpired?: boolean;
  };
  authorizationResult?: {
    authorized: boolean;
    reason?: string;
  };
  securityIssues?: string[];
  vulnerabilityDetails?: {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    recommendation?: string;
  }[];
  details?: Record<string, any>;
  error?: string;
  timestamp: Date | string;
  createdAt: Date | string;
}

