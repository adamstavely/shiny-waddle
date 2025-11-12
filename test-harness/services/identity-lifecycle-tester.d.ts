import { User, TestResult } from '../core/types';
export interface IdentitySystemProvider {
    isMFAEnabled(userId: string): Promise<boolean>;
    checkCredentialAge(userId: string): Promise<{
        passwordAge?: number;
        apiKeyAge?: number;
        certificateExpiration?: Date;
        mfaTokenAge?: number;
    }>;
    getMFAStatus(userId: string): Promise<{
        enabled: boolean;
        requiredForAdmin: boolean;
        backupCodesGenerated: boolean;
        deviceRegistered: boolean;
    }>;
}
export interface IdentityLifecycleTesterConfig {
    identityProvider?: IdentitySystemProvider;
    mockData?: {
        mfaEnabled?: boolean;
        credentialAges?: {
            passwordAge?: number;
            apiKeyAge?: number;
            certificateExpiration?: Date;
            mfaTokenAge?: number;
        };
        mfaStatus?: {
            enabled: boolean;
            requiredForAdmin: boolean;
            backupCodesGenerated: boolean;
            deviceRegistered: boolean;
        };
    };
}
export declare class IdentityLifecycleTester {
    private config;
    private identityProvider?;
    constructor(config?: IdentityLifecycleTesterConfig);
    testOnboardingWorkflow(user: User): Promise<TestResult>;
    testRoleChangeWorkflow(user: User, newRole: string): Promise<TestResult>;
    testOffboardingWorkflow(user: User): Promise<TestResult>;
    validateCredentialRotation(user: User): Promise<TestResult>;
    testMFAEnforcement(user: User): Promise<TestResult>;
}
