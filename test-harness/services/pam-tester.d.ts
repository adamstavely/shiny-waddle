import { TestResult, PAMRequest, PAMWorkflow } from '../core/types';
export interface PAMSystemProvider {
    isUserAuthorized(userId: string, resource: string): Promise<boolean>;
    isResourceAccessible(resource: string): Promise<boolean>;
    hasEmergencyPermissions(userId: string): Promise<boolean>;
}
export interface PAMTesterConfig {
    pamProvider?: PAMSystemProvider;
    mockData?: {
        userAuthorized?: boolean;
        resourceAccessible?: boolean;
        emergencyPermissions?: boolean;
    };
    maxJITDuration?: number;
}
export declare class PAMTester {
    private config;
    private pamProvider?;
    constructor(config?: PAMTesterConfig);
    testJITAccess(request: PAMRequest): Promise<TestResult>;
    testBreakGlassAccess(emergencyRequest: PAMRequest): Promise<TestResult>;
    validatePAMWorkflows(workflows: PAMWorkflow[]): Promise<TestResult[]>;
    testWorkflowExecution(workflow: PAMWorkflow, request: PAMRequest): Promise<TestResult>;
}
