import { Dataset, PrivacyThreshold, StatisticalFidelityTarget, DatasetHealthConfig } from '../core/types';
export interface DatasetHealthTestInput {
    dataset: Dataset;
    privacyThresholds?: PrivacyThreshold[];
    statisticalFidelityTargets?: StatisticalFidelityTarget[];
}
export interface DatasetHealthTestResult {
    compliant: boolean;
    datasetName: string;
    privacyResults: PrivacyTestResult[];
    statisticalResults: StatisticalTestResult[];
    violations: string[];
    recommendations: string[];
}
export interface PrivacyTestResult {
    metric: string;
    value: number;
    threshold: number;
    passed: boolean;
}
export interface StatisticalTestResult {
    field: string;
    metric: string;
    actualValue: number;
    targetValue?: number;
    tolerance?: number;
    passed: boolean;
}
export declare class DatasetHealthTester {
    private config;
    constructor(config: DatasetHealthConfig);
    testDataset(input: DatasetHealthTestInput): Promise<DatasetHealthTestResult>;
    private testPrivacyThreshold;
    private calculateKAnonymity;
    private calculateLDiversity;
    private calculateTCloseness;
    private calculateDifferentialPrivacy;
    private testStatisticalFidelity;
    private calculateMean;
    private calculateMedian;
    private calculateStdDev;
    private calculateDistributionSimilarity;
    private evaluateThreshold;
}
