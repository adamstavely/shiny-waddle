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
    type: AuthenticationType;
    credentials: Record<string, string>;
  };
  rateLimitConfig?: {
    maxRequests?: number;
    windowSeconds?: number;
    strategy?: 'fixed' | 'sliding' | 'token-bucket';
  };
  headers?: Record<string, string>;
  timeout?: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface APIEndpointEntity {
  id: string;
  configId: string;
  name: string;
  endpoint: string;
  method: HTTPMethod;
  apiType: APITestType;
  expectedStatus?: number;
  expectedAuthRequired?: boolean;
  expectedRateLimit?: boolean;
  body?: any;
  headers?: Record<string, string>;
  createdAt: Date;
  updatedAt: Date;
}

export interface APISecurityTestResultEntity {
  id: string;
  configId: string;
  endpointId?: string;
  testName: string;
  endpoint: string;
  method: HTTPMethod;
  testType: APITestType;
  status: 'passed' | 'failed' | 'warning';
  statusCode?: number;
  responseTime?: number;
  rateLimitInfo?: {
    limit?: number;
    remaining?: number;
    resetTime?: Date;
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
  timestamp: Date;
  createdAt: Date;
}

