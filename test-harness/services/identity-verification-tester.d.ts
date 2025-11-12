import { User, TestResult } from '../core/types';
export declare class IdentityVerificationTester {
    testIdentityVerification(user: User, method: 'password' | 'mfa' | 'certificate' | 'biometric'): Promise<TestResult>;
    testMFA(user: User): Promise<TestResult>;
    testIdentityProofing(user: User): Promise<TestResult>;
}
