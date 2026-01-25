/**
 * Data Pipeline Testing Example
 * 
 * Demonstrates how to use the Data Pipeline Tester to test ETL pipelines,
 * streaming data, and pipeline security.
 * 
 * IMPORTANT: All endpoints and connection strings should be provided via
 * runtime configuration (environment variables or config files), not hardcoded.
 */

import { DataPipelineTester } from '../heimdall-framework/services/data-pipeline-tester';
import { User } from '../heimdall-framework/core/types';
import { loadRuntimeConfigFromEnv } from '../heimdall-framework/core/config-loader';

async function main() {
  // Load runtime configuration from environment variables
  const runtimeConfig = loadRuntimeConfigFromEnv();

  // Validate that required configuration is present
  if (!runtimeConfig.database) {
    throw new Error(
      'Database configuration is required. Set TEST_DATABASE_* environment variables ' +
      'or provide database config in runtime configuration.'
    );
  }

  // Initialize Data Pipeline Tester for ETL
  // Use endpoints and connection strings from runtime config
  const etlTester = new DataPipelineTester({
    pipelineType: 'etl',
    connection: {
      type: 'airflow',
      // Use endpoint from runtime config if available
      endpoint: runtimeConfig.endpoints?.airflow || process.env.AIRFLOW_ENDPOINT || 'http://airflow.example.com:8080',
      credentials: {
        username: process.env.AIRFLOW_USER || 'admin',
        password: process.env.AIRFLOW_PASSWORD || 'admin',
      },
    },
    dataSource: {
      type: 'database',
      // Use database connection from runtime config
      connectionString: runtimeConfig.database.connectionString || 
        `postgresql://${runtimeConfig.database.host || 'source-db'}:${runtimeConfig.database.port || 5432}/${runtimeConfig.database.database || 'mydb'}`,
    },
    dataDestination: {
      type: 'data-warehouse',
      // Use destination from runtime config if available
      connectionString: process.env.DATA_WAREHOUSE_CONNECTION || 'snowflake://warehouse.example.com',
    },
  });

  // Example 1: Test ETL Pipeline
  console.log('Testing ETL Pipeline...');
  const etlResult = await etlTester.testETLPipeline({
    name: 'User Data ETL Pipeline',
    pipelineId: 'user-data-etl',
    stage: 'all',
    expectedAccess: true,
    user: {
      id: 'pipeline-user-1',
      email: 'pipeline@example.com',
      role: 'researcher',
      attributes: {},
    },
    dataValidation: {
      schema: {
        id: 'string',
        name: 'string',
        email: 'string',
        created_at: 'datetime',
      },
      constraints: ['NOT NULL id', 'UNIQUE id', 'NOT NULL email'],
      qualityRules: [
        'completeness > 0.9',
        'uniqueness > 0.95',
        'validity > 0.98',
      ],
    },
  });

  console.log('ETL Pipeline Test Result:', {
    passed: etlResult.passed,
    accessGranted: etlResult.accessGranted,
    dataValidation: etlResult.dataValidation,
    transformationResult: etlResult.transformationResult,
    securityIssues: etlResult.securityIssues,
    performanceMetrics: etlResult.performanceMetrics,
  });

  // Example 2: Test Streaming Data (Kafka)
  console.log('\nTesting Streaming Data...');
  // Use Kafka endpoint from runtime config if available
  const kafkaEndpoint = runtimeConfig.endpoints?.kafka || process.env.KAFKA_ENDPOINT || 'kafka.example.com:9092';
  const streamingTester = new DataPipelineTester({
    pipelineType: 'streaming',
    connection: {
      type: 'kafka',
      endpoint: kafkaEndpoint,
      credentials: {
        username: process.env.KAFKA_USER || 'kafka-user',
        password: process.env.KAFKA_PASSWORD || 'kafka-pass',
      },
    },
  });

  const streamingResult = await streamingTester.testStreamingData({
    name: 'Kafka Streaming Test',
    pipelineId: 'user-events-topic',
    expectedAccess: true,
    user: {
      id: 'stream-user-1',
      email: 'stream@example.com',
      role: 'analyst',
      attributes: {},
    },
  });

  console.log('Streaming Data Test Result:', {
    passed: streamingResult.passed,
    accessGranted: streamingResult.accessGranted,
    performanceMetrics: streamingResult.performanceMetrics,
  });

  // Example 3: Test Data Transformation
  console.log('\nTesting Data Transformation...');
  const transformResult = await etlTester.testDataTransformation({
    name: 'Data Transformation Test',
    pipelineId: 'transform-pipeline',
    expectedAccess: true,
    user: {
      id: 'transform-user-1',
      email: 'transform@example.com',
      role: 'researcher',
      attributes: {},
    },
  });

  console.log('Data Transformation Test Result:', {
    passed: transformResult.passed,
    accessGranted: transformResult.accessGranted,
    transformationResult: transformResult.transformationResult,
    performanceMetrics: transformResult.performanceMetrics,
  });

  // Example 4: Test Pipeline Security
  console.log('\nTesting Pipeline Security...');
  const securityResult = await etlTester.testPipelineSecurity({
    name: 'Pipeline Security Test',
    pipelineId: 'secure-pipeline',
    user: {
      id: 'security-user-1',
      email: 'security@example.com',
      role: 'admin',
      attributes: {},
    },
  });

  console.log('Pipeline Security Test Result:', {
    passed: securityResult.passed,
    securityIssues: securityResult.securityIssues,
    details: {
      encryptionInTransit: securityResult.details?.encryptionInTransit,
      encryptionAtRest: securityResult.details?.encryptionAtRest,
      accessLogging: securityResult.details?.accessLogging,
      dataMasking: securityResult.details?.dataMasking,
      networkIsolation: securityResult.details?.networkIsolation,
    },
  });

  // Example 5: Test individual pipeline stages
  console.log('\nTesting Individual Pipeline Stages...');

  // Test Extract stage
  const extractResult = await etlTester.testETLPipeline({
    name: 'Extract Stage Test',
    pipelineId: 'extract-test',
    stage: 'extract',
    expectedAccess: true,
  });

  console.log('Extract Stage Result:', {
    passed: extractResult.passed,
    accessGranted: extractResult.accessGranted,
  });

  // Test Transform stage
  const transformStageResult = await etlTester.testETLPipeline({
    name: 'Transform Stage Test',
    pipelineId: 'transform-test',
    stage: 'transform',
    expectedAccess: true,
  });

  console.log('Transform Stage Result:', {
    passed: transformStageResult.passed,
    transformationResult: transformStageResult.transformationResult,
  });

  // Test Load stage
  const loadResult = await etlTester.testETLPipeline({
    name: 'Load Stage Test',
    pipelineId: 'load-test',
    stage: 'load',
    expectedAccess: true,
  });

  console.log('Load Stage Result:', {
    passed: loadResult.passed,
    accessGranted: loadResult.accessGranted,
  });
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { main as runDataPipelineTests };

