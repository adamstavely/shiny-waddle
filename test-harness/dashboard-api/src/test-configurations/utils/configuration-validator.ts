import {
  RLSCLSConfigurationEntity,
  DLPConfigurationEntity,
  APIGatewayConfigurationEntity,
  NetworkPolicyConfigurationEntity,
  TestConfigurationEntity,
} from '../entities/test-configuration.entity';

export interface ValidationError {
  field: string;
  message: string;
  suggestion?: string;
}

export function validateRLSCLSConfig(config: RLSCLSConfigurationEntity): ValidationError[] {
  const errors: ValidationError[] = [];

  if (!config.database) {
    errors.push({
      field: 'database',
      message: 'Database configuration is required for RLS/CLS tests',
      suggestion: 'Add a database configuration with connection details',
    });
  } else {
    if (!config.database.type) {
      errors.push({
        field: 'database.type',
        message: 'Database type is required',
        suggestion: 'Specify the database type (e.g., postgresql, mysql)',
      });
    }
  }

  if (!config.testQueries || config.testQueries.length === 0) {
    errors.push({
      field: 'testQueries',
      message: 'At least one test query is required for RLS/CLS tests',
      suggestion: 'Add test queries to validate RLS/CLS policies',
    });
  }

  return errors;
}

export function validateDLPConfig(config: DLPConfigurationEntity): ValidationError[] {
  const errors: ValidationError[] = [];

  // DLP configs are more flexible - patterns are optional but recommended
  if (!config.patterns || config.patterns.length === 0) {
    errors.push({
      field: 'patterns',
      message: 'DLP patterns are recommended for effective data loss prevention testing',
      suggestion: 'Add DLP patterns to detect sensitive data (e.g., SSN, credit card numbers)',
    });
  }

  return errors;
}

export function validateAPIGatewayConfig(config: APIGatewayConfigurationEntity): ValidationError[] {
  const errors: ValidationError[] = [];

  // API Gateway configs are flexible
  // Rate limit config is recommended for rate limiting tests
  if (!config.rateLimitConfig) {
    errors.push({
      field: 'rateLimitConfig',
      message: 'Rate limit configuration is recommended for API Gateway tests',
      suggestion: 'Add rate limit configuration to test API throttling',
    });
  }

  // Gateway policies are recommended for policy tests
  if (!config.gatewayPolicies || config.gatewayPolicies.length === 0) {
    errors.push({
      field: 'gatewayPolicies',
      message: 'Gateway policies are recommended for API Gateway policy tests',
      suggestion: 'Add gateway policies to test API access control',
    });
  }

  return errors;
}

export function validateNetworkPolicyConfig(
  config: NetworkPolicyConfigurationEntity,
): ValidationError[] {
  const errors: ValidationError[] = [];

  if (!config.firewallRules || config.firewallRules.length === 0) {
    errors.push({
      field: 'firewallRules',
      message: 'Firewall rules are required for network policy tests',
      suggestion: 'Add firewall rules to test network access control',
    });
  }

  if (!config.networkSegments || config.networkSegments.length === 0) {
    errors.push({
      field: 'networkSegments',
      message: 'Network segments are required for network segmentation tests',
      suggestion: 'Add network segments to test network isolation',
    });
  }

  return errors;
}

export function validateConfiguration(config: TestConfigurationEntity): ValidationError[] {
  switch (config.type) {
    case 'rls-cls':
      return validateRLSCLSConfig(config as RLSCLSConfigurationEntity);
    case 'dlp':
      return validateDLPConfig(config as DLPConfigurationEntity);
    case 'api-gateway':
      return validateAPIGatewayConfig(config as APIGatewayConfigurationEntity);
    case 'network-policy':
      return validateNetworkPolicyConfig(config as NetworkPolicyConfigurationEntity);
    default:
      return [
        {
          field: 'type',
          message: `Unknown configuration type: ${(config as any).type}`,
          suggestion: 'Use a valid configuration type',
        },
      ];
  }
}

export function formatValidationErrors(errors: ValidationError[], configName?: string): string {
  if (errors.length === 0) {
    return '';
  }

  const prefix = configName ? `Configuration '${configName}' has validation issues:\n` : 'Configuration validation issues:\n';
  const errorMessages = errors.map((err, index) => {
    let msg = `${index + 1}. ${err.field}: ${err.message}`;
    if (err.suggestion) {
      msg += `\n   Suggestion: ${err.suggestion}`;
    }
    return msg;
  });

  return prefix + errorMessages.join('\n');
}

