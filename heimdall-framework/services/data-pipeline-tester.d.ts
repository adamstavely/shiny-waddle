import { User, Resource } from '../core/types';
import { TestResult } from '../core/types';
export interface PipelineTestConfig {
    pipelineType: 'etl' | 'streaming' | 'batch' | 'real-time';
    connection?: {
        type: 'kafka' | 'spark' | 'airflow' | 'dbt' | 'custom';
        endpoint?: string;
        credentials?: Record<string, string>;
    };
    dataSource?: {
        type: 'database' | 'api' | 'file' | 'stream';
        connectionString?: string;
    };
    dataDestination?: {
        type: 'database' | 'data-warehouse' | 'data-lake' | 'api';
        connectionString?: string;
    };
}
export interface PipelineTest {
    name: string;
    pipelineId: string;
    stage: 'extract' | 'transform' | 'load' | 'all';
    user?: User;
    resource?: Resource;
    expectedAccess?: boolean;
    dataValidation?: {
        schema?: Record<string, any>;
        constraints?: string[];
        qualityRules?: string[];
    };
}
export interface PipelineTestResult extends TestResult {
    testName: string;
    pipelineId: string;
    stage: string;
    accessGranted: boolean;
    dataValidation?: {
        passed: boolean;
        errors: string[];
        warnings: string[];
    };
    transformationResult?: {
        inputRecords: number;
        outputRecords: number;
        transformations: string[];
        errors: string[];
    };
    securityIssues?: string[];
    performanceMetrics?: {
        executionTime: number;
        throughput: number;
        latency: number;
    };
}
export declare class DataPipelineTester {
    private config;
    constructor(config: PipelineTestConfig);
    testETLPipeline(test: PipelineTest): Promise<PipelineTestResult>;
    testStreamingData(test: PipelineTest): Promise<PipelineTestResult>;
    testDataTransformation(test: PipelineTest): Promise<PipelineTestResult>;
    testPipelineSecurity(test: PipelineTest): Promise<PipelineTestResult>;
    private testExtractStage;
    private testTransformStage;
    private testLoadStage;
    private testKafkaStreaming;
    private testGenericStreaming;
    private executeTransformation;
    private checkPipelineAccess;
    private checkTransformationAccess;
    private validatePipelineData;
    private detectPipelineSecurityIssues;
    private collectPerformanceMetrics;
    private testEncryptionInTransit;
    private testEncryptionAtRest;
    private testAccessLogging;
    private testDataMasking;
    private testNetworkIsolation;
    private testKafkaConsume;
    private testKafkaProduce;
}
