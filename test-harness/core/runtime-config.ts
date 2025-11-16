/**
 * Runtime Test Configuration
 * 
 * Configuration values that should be provided at runtime rather than
 * hardcoded in test definitions. This allows tests to be environment-agnostic.
 */

import { DatabaseConfig, Context } from './types';

/**
 * Authentication configuration for runtime tests
 */
export interface AuthConfig {
  type: 'bearer' | 'basic' | 'oauth2' | 'api-key' | 'jwt';
  credentials: Record<string, string>;
}

/**
 * Region configuration for distributed systems tests
 */
export interface RegionConfig {
  id: string;
  name: string;
  endpoint: string;
  pdpEndpoint?: string;
  timezone?: string;
  latency?: number;
  credentials?: {
    token?: string;
    [key: string]: any;
  };
}

/**
 * Runtime test configuration
 * 
 * All values that should be provided at runtime instead of being hardcoded
 * in test definitions. This includes URLs, endpoints, application names,
 * database connections, authentication, and other environment-specific values.
 */
export interface RuntimeTestConfig {
  /**
   * Application name being tested
   */
  applicationName?: string;

  /**
   * Base URL for API tests (e.g., 'https://api.example.com')
   */
  baseUrl?: string;

  /**
   * Named endpoint mappings (e.g., { users: '/api/v1/users', admin: '/api/v1/admin' })
   */
  endpoints?: Record<string, string>;

  /**
   * Database connection details
   */
  database?: DatabaseConfig;

  /**
   * Authentication configuration
   */
  authentication?: AuthConfig;

  /**
   * Runtime contexts (IP addresses, locations, etc.)
   */
  contexts?: Context[];

  /**
   * Environment identifier (dev/staging/prod)
   */
  environment?: string;

  /**
   * Region configurations for distributed systems tests
   */
  regionConfigs?: RegionConfig[];

  /**
   * Endpoint patterns for enumeration tests (e.g., ['/admin', '/api/admin'])
   */
  endpointPatterns?: string[];

  /**
   * Additional custom configuration values
   */
  [key: string]: any;
}

/**
 * Validation result for runtime configuration
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings?: string[];
}

