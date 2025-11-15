/**
 * Environment Configuration Testing Usage Example
 * 
 * Demonstrates how to use the environment configuration testing services
 */

import { EnvironmentConfigValidator, EnvironmentConfig } from '../services/environment-config-validator';
import { SecretsManagementValidator, SecretsManagerConfig } from '../services/secrets-management-validator';
import { ConfigDriftDetector } from '../services/config-drift-detector';
import { EnvironmentPolicyValidator, EnvironmentPolicy } from '../services/environment-policy-validator';
import { EnvironmentConfigTestSuite } from '../services/test-suites/environment-config-test-suite';

async function main() {
  // Example 1: Validate environment variables
  console.log('=== Example 1: Environment Variable Validation ===');
  const envValidator = new EnvironmentConfigValidator();
  
  const envConfig: EnvironmentConfig = {
    environment: 'prod',
    variables: {
      DATABASE_URL: 'postgresql://user:password@localhost:5432/db',
      API_KEY: 'sk_live_1234567890abcdef',
      NODE_ENV: 'production',
    },
    configFiles: ['./config/prod.json'],
    secrets: ['DATABASE_URL', 'API_KEY'],
  };

  const validationResult = await envValidator.validateEnvironmentVariables(envConfig);
  console.log('Validation Result:', validationResult);
  console.log(`Passed: ${validationResult.passed}`);
  console.log(`Issues Found: ${validationResult.issues.length}`);

  // Example 2: Validate secrets management
  console.log('\n=== Example 2: Secrets Management Validation ===');
  const secretsValidator = new SecretsManagementValidator();
  
  const secretsConfig: SecretsManagerConfig = {
    type: 'vault',
    connection: {
      address: 'https://vault.example.com',
      token: 'vault-token',
    },
  };

  const secretsResult = await secretsValidator.validateSecretsStorage(secretsConfig);
  console.log('Secrets Validation Result:', secretsResult);
  console.log(`Passed: ${secretsResult.passed}`);

  // Example 3: Detect configuration drift
  console.log('\n=== Example 3: Configuration Drift Detection ===');
  const driftDetector = new ConfigDriftDetector();
  
  // Create baseline
  const baseline = await driftDetector.createBaseline('prod', envConfig);
  console.log('Baseline Created:', baseline.timestamp);

  // Simulate current config with changes
  const currentConfig: EnvironmentConfig = {
    ...envConfig,
    variables: {
      ...envConfig.variables,
      NEW_VAR: 'new-value',
      DATABASE_URL: 'postgresql://user:newpassword@localhost:5432/db', // Changed
    },
  };

  const driftResult = await driftDetector.detectDrift(baseline, currentConfig);
  console.log('Drift Detection Result:', driftResult);
  console.log(`Has Drift: ${driftResult.hasDrift}`);
  console.log(`Drift Score: ${driftResult.driftScore}`);

  // Example 4: Validate environment policies
  console.log('\n=== Example 4: Environment Policy Validation ===');
  const policyValidator = new EnvironmentPolicyValidator();
  
  const envPolicy: EnvironmentPolicy = {
    environment: 'prod',
    policies: [],
    isolationRules: [
      {
        fromEnvironment: 'prod',
        toEnvironment: 'dev',
        allowed: false,
      },
    ],
    promotionRules: [
      {
        fromEnvironment: 'staging',
        toEnvironment: 'prod',
        requiredApprovals: 2,
        requiredChecks: ['security-review', 'compliance-check'],
      },
    ],
  };

  const policyResult = await policyValidator.validateEnvironmentPolicies(envPolicy);
  console.log('Policy Validation Result:', policyResult);
  console.log(`Passed: ${policyResult.passed}`);

  // Example 5: Run complete test suite
  console.log('\n=== Example 5: Complete Test Suite ===');
  const testSuite = new EnvironmentConfigTestSuite();
  
  const suiteConfig = {
    environments: ['dev', 'staging', 'prod'],
    baselineEnvironment: 'prod',
    configFiles: ['./config/prod.json'],
    secretsManager: secretsConfig,
    policies: [envPolicy],
  };

  const suiteResults = await testSuite.runAllTests(suiteConfig);
  console.log(`Total Tests: ${suiteResults.length}`);
  console.log(`Passed: ${suiteResults.filter(r => r.passed).length}`);
  console.log(`Failed: ${suiteResults.filter(r => !r.passed).length}`);
}

main().catch(console.error);

