/**
 * Configuration Loader
 * 
 * Utilities for loading runtime test configuration from various sources
 * (environment variables, config files) and merging with test suites.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { RuntimeTestConfig, ValidationResult } from './runtime-config';
import { TestSuite, Context, DatabaseConfig } from './types';

/**
 * Load runtime configuration from environment variables
 * 
 * Environment variable naming convention:
 * - TEST_APPLICATION_NAME -> applicationName
 * - TEST_BASE_URL -> baseUrl
 * - TEST_ENDPOINT_<NAME> -> endpoints[name]
 * - TEST_DATABASE_HOST -> database.host
 * - TEST_DATABASE_PORT -> database.port
 * - TEST_DATABASE_NAME -> database.database
 * - TEST_DATABASE_TYPE -> database.type
 * - TEST_AUTH_TYPE -> authentication.type
 * - TEST_AUTH_TOKEN -> authentication.credentials.token
 * - TEST_ENVIRONMENT -> environment
 */
export function loadRuntimeConfigFromEnv(): RuntimeTestConfig {
  const config: RuntimeTestConfig = {};

  // Application name
  if (process.env.TEST_APPLICATION_NAME) {
    config.applicationName = process.env.TEST_APPLICATION_NAME;
  }

  // Base URL
  if (process.env.TEST_BASE_URL) {
    config.baseUrl = process.env.TEST_BASE_URL;
  }

  // Endpoints - collect all TEST_ENDPOINT_* variables
  const endpoints: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith('TEST_ENDPOINT_')) {
      const endpointName = key.replace('TEST_ENDPOINT_', '').toLowerCase();
      endpoints[endpointName] = value;
    }
  }
  if (Object.keys(endpoints).length > 0) {
    config.endpoints = endpoints;
  }

  // Database configuration
  const database: Partial<DatabaseConfig> = {};
  if (process.env.TEST_DATABASE_TYPE) {
    database.type = process.env.TEST_DATABASE_TYPE as any;
  }
  if (process.env.TEST_DATABASE_HOST) {
    database.host = process.env.TEST_DATABASE_HOST;
  }
  if (process.env.TEST_DATABASE_PORT) {
    database.port = parseInt(process.env.TEST_DATABASE_PORT, 10);
  }
  if (process.env.TEST_DATABASE_NAME) {
    database.database = process.env.TEST_DATABASE_NAME;
  }
  if (process.env.TEST_DATABASE_USERNAME) {
    database.username = process.env.TEST_DATABASE_USERNAME;
  }
  if (process.env.TEST_DATABASE_PASSWORD) {
    database.password = process.env.TEST_DATABASE_PASSWORD;
  }
  if (process.env.TEST_DATABASE_CONNECTION_STRING) {
    database.connectionString = process.env.TEST_DATABASE_CONNECTION_STRING;
  }
  if (Object.keys(database).length > 0) {
    config.database = database as DatabaseConfig;
  }

  // Authentication
  if (process.env.TEST_AUTH_TYPE) {
    config.authentication = {
      type: process.env.TEST_AUTH_TYPE as any,
      credentials: {},
    };
    // Collect all TEST_AUTH_* variables (except TYPE)
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith('TEST_AUTH_') && key !== 'TEST_AUTH_TYPE') {
        const credKey = key.replace('TEST_AUTH_', '').toLowerCase();
        if (config.authentication) {
          config.authentication.credentials[credKey] = value;
        }
      }
    }
  }

  // Environment
  if (process.env.TEST_ENVIRONMENT) {
    config.environment = process.env.TEST_ENVIRONMENT;
  }

  // Contexts - parse from TEST_CONTEXTS JSON array
  if (process.env.TEST_CONTEXTS) {
    try {
      config.contexts = JSON.parse(process.env.TEST_CONTEXTS) as Context[];
    } catch (e) {
      console.warn('Failed to parse TEST_CONTEXTS:', e);
    }
  }

  // Endpoint patterns - parse from TEST_ENDPOINT_PATTERNS JSON array
  if (process.env.TEST_ENDPOINT_PATTERNS) {
    try {
      config.endpointPatterns = JSON.parse(process.env.TEST_ENDPOINT_PATTERNS) as string[];
    } catch (e) {
      console.warn('Failed to parse TEST_ENDPOINT_PATTERNS:', e);
    }
  }

  // Region configs - parse from TEST_REGION_CONFIGS JSON array
  if (process.env.TEST_REGION_CONFIGS) {
    try {
      config.regionConfigs = JSON.parse(process.env.TEST_REGION_CONFIGS);
    } catch (e) {
      console.warn('Failed to parse TEST_REGION_CONFIGS:', e);
    }
  }

  return config;
}

/**
 * Load runtime configuration from a JSON or YAML file
 */
export async function loadRuntimeConfigFromFile(
  filePath: string
): Promise<RuntimeTestConfig> {
  const fullPath = path.resolve(filePath);
  const fileContent = await fs.readFile(fullPath, 'utf-8');
  const ext = path.extname(fullPath).toLowerCase();

  if (ext === '.json') {
    return JSON.parse(fileContent) as RuntimeTestConfig;
  } else if (ext === '.yaml' || ext === '.yml') {
    // For YAML support, we'd need to add a YAML parser dependency
    // For now, we'll throw an error suggesting JSON
    throw new Error(
      'YAML support not yet implemented. Please use a JSON config file.'
    );
  } else {
    // Try to parse as JSON
    try {
      return JSON.parse(fileContent) as RuntimeTestConfig;
    } catch (e) {
      throw new Error(
        `Unsupported config file format: ${ext}. Please use JSON.`
      );
    }
  }
}

/**
 * Merge runtime configuration into a test suite
 * 
 * Runtime config values override test suite defaults.
 * This allows tests to be environment-agnostic.
 */
export function mergeRuntimeConfig(
  suite: TestSuite,
  runtimeConfig: RuntimeTestConfig
): TestSuite {
  const merged: TestSuite = {
    ...suite,
    runtimeConfig,
  };

  // Override application name if provided in runtime config
  if (runtimeConfig.applicationName) {
    merged.application = runtimeConfig.applicationName;
  }

  return merged;
}

/**
 * Validate runtime configuration
 * 
 * Checks that required configuration values are present
 * based on the test type and configuration provided.
 */
export function validateRuntimeConfig(
  config: RuntimeTestConfig,
  testType?: string
): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate based on test type
  if (testType === 'api-security' || testType === 'api-gateway') {
    if (!config.baseUrl) {
      errors.push('baseUrl is required for API security/gateway tests');
    }
  }

  if (testType === 'rls-cls') {
    if (!config.database) {
      errors.push('database configuration is required for RLS/CLS tests');
    } else {
      if (!config.database.host && !config.database.connectionString) {
        errors.push(
          'database.host or database.connectionString is required for RLS/CLS tests'
        );
      }
    }
  }

  if (testType === 'distributed-systems') {
    if (!config.regionConfigs || config.regionConfigs.length === 0) {
      errors.push(
        'regionConfigs is required for distributed systems tests'
      );
    }
  }

  // General validations
  if (config.baseUrl && !config.baseUrl.match(/^https?:\/\//)) {
    warnings.push('baseUrl should start with http:// or https://');
  }

  if (config.database) {
    if (config.database.port && (config.database.port < 1 || config.database.port > 65535)) {
      errors.push('database.port must be between 1 and 65535');
    }
  }

  if (config.authentication) {
    if (!config.authentication.type) {
      errors.push('authentication.type is required when authentication is provided');
    }
    if (
      !config.authentication.credentials ||
      Object.keys(config.authentication.credentials).length === 0
    ) {
      warnings.push('authentication.credentials should be provided');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
}

/**
 * Resolve endpoint from runtime config
 * 
 * If endpoint is a named reference (e.g., 'users'), look it up in config.endpoints.
 * Otherwise, return the endpoint as-is.
 */
export function resolveEndpoint(
  endpoint: string,
  config?: RuntimeTestConfig
): string {
  if (!config || !config.endpoints) {
    return endpoint;
  }

  // If endpoint starts with '/', it's already a path
  if (endpoint.startsWith('/')) {
    return endpoint;
  }

  // Otherwise, try to resolve from named endpoints
  return config.endpoints[endpoint] || endpoint;
}

/**
 * Get full URL from base URL and endpoint
 */
export function getFullUrl(
  endpoint: string,
  config?: RuntimeTestConfig
): string {
  const resolvedEndpoint = resolveEndpoint(endpoint, config);
  
  if (!config || !config.baseUrl) {
    return resolvedEndpoint;
  }

  // If endpoint already includes protocol, return as-is
  if (resolvedEndpoint.match(/^https?:\/\//)) {
    return resolvedEndpoint;
  }

  // Combine baseUrl and endpoint
  const base = config.baseUrl.endsWith('/')
    ? config.baseUrl.slice(0, -1)
    : config.baseUrl;
  const ep = resolvedEndpoint.startsWith('/')
    ? resolvedEndpoint
    : '/' + resolvedEndpoint;

  return base + ep;
}

