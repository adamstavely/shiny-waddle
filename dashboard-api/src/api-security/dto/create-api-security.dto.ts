import { APITestType, HTTPMethod, AuthenticationType } from '../entities/api-security.entity';

export interface CreateAPISecurityConfigDto {
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
}

export interface CreateAPIEndpointDto {
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
}

export interface CreateAPISecurityTestDto {
  configId: string;
  endpointId?: string;
  testName: string;
  endpoint: string;
  method: HTTPMethod;
  testType: APITestType;
  body?: any;
  headers?: Record<string, string>;
}

export interface UpdateAPISecurityConfigDto {
  name?: string;
  baseUrl?: string;
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
}

