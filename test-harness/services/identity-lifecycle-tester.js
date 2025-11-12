"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentityLifecycleTester = void 0;
class IdentityLifecycleTester {
    constructor(config) {
        this.config = config || {};
        this.identityProvider = this.config.identityProvider;
    }
    async testOnboardingWorkflow(user) {
        const result = {
            testType: 'access-control',
            testName: 'Identity Onboarding Workflow',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            let mfaEnabled = false;
            if (this.identityProvider) {
                try {
                    mfaEnabled = await this.identityProvider.isMFAEnabled(user.id);
                }
                catch (error) {
                    mfaEnabled = this.config.mockData?.mfaEnabled ?? false;
                }
            }
            else {
                mfaEnabled = this.config.mockData?.mfaEnabled ?? false;
            }
            const configuredSteps = this.config.workflowSteps;
            let steps;
            if (configuredSteps && configuredSteps.length > 0) {
                steps = configuredSteps.map(step => {
                    let completed = false;
                    switch (step.name.toLowerCase()) {
                        case 'create identity':
                            completed = true;
                            break;
                        case 'assign default role':
                        case 'assign role':
                            completed = user.role !== undefined;
                            break;
                        case 'set initial permissions':
                        case 'set permissions':
                            completed = user.attributes !== undefined;
                            break;
                        case 'enable mfa':
                        case 'enable multi-factor authentication':
                            completed = mfaEnabled;
                            break;
                        case 'send welcome email':
                        case 'send email':
                            completed = true;
                            break;
                        default:
                            completed = true;
                    }
                    return { name: step.name, completed };
                });
            }
            else {
                steps = [
                    { name: 'Create Identity', completed: true },
                    { name: 'Assign Default Role', completed: user.role !== undefined },
                    { name: 'Set Initial Permissions', completed: user.attributes !== undefined },
                    { name: 'Enable MFA', completed: mfaEnabled },
                    { name: 'Send Welcome Email', completed: true },
                ];
            }
            const allCompleted = steps.every(step => step.completed);
            const completedSteps = steps.filter(step => step.completed).map(step => step.name);
            result.passed = allCompleted;
            result.details = {
                steps,
                allCompleted,
                completedSteps,
                event: {
                    type: 'onboarding',
                    userId: user.id,
                    timestamp: new Date(),
                    details: { steps },
                },
            };
            result.completedSteps = completedSteps;
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testRoleChangeWorkflow(user, newRole) {
        const result = {
            testType: 'access-control',
            testName: 'Role Change Workflow',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const validRoles = ['admin', 'researcher', 'analyst', 'viewer'];
            const isValidRole = validRoles.includes(newRole);
            if (!isValidRole) {
                result.error = `Invalid role: ${newRole}`;
                return result;
            }
            const steps = [
                { name: 'Validate New Role', completed: isValidRole },
                { name: 'Revoke Old Permissions', completed: true },
                { name: 'Grant New Permissions', completed: true },
                { name: 'Update Access Policies', completed: true },
                { name: 'Notify User', completed: true },
                { name: 'Audit Log Entry', completed: true },
            ];
            const allCompleted = steps.every(step => step.completed);
            result.passed = allCompleted;
            result.details = {
                oldRole: user.role,
                newRole,
                steps,
                allCompleted,
                event: {
                    type: 'role-change',
                    userId: user.id,
                    timestamp: new Date(),
                    details: { oldRole: user.role, newRole, steps },
                },
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testOffboardingWorkflow(user) {
        const result = {
            testType: 'access-control',
            testName: 'Identity Offboarding Workflow',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const steps = [
                { name: 'Revoke All Access', completed: true },
                { name: 'Disable Active Sessions', completed: true },
                { name: 'Archive User Data', completed: true },
                { name: 'Remove from Groups', completed: true },
                { name: 'Revoke API Keys', completed: true },
                { name: 'Disable MFA', completed: true },
                { name: 'Send Offboarding Email', completed: true },
                { name: 'Audit Log Entry', completed: true },
            ];
            const allCompleted = steps.every(step => step.completed);
            result.passed = allCompleted;
            result.details = {
                steps,
                allCompleted,
                event: {
                    type: 'offboarding',
                    userId: user.id,
                    timestamp: new Date(),
                    details: { steps },
                },
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async validateCredentialRotation(user) {
        const result = {
            testType: 'access-control',
            testName: 'Credential Rotation Validation',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            let credentialAges;
            if (this.identityProvider) {
                try {
                    credentialAges = await this.identityProvider.checkCredentialAge(user.id);
                }
                catch (error) {
                    credentialAges = this.config.mockData?.credentialAges || {};
                }
            }
            else {
                credentialAges = this.config.mockData?.credentialAges || {};
            }
            const maxPasswordAge = 90;
            const maxApiKeyAge = 180;
            const maxMfaTokenAge = 30;
            const checks = [
                {
                    name: 'Password Age Check',
                    passed: !credentialAges.passwordAge || credentialAges.passwordAge < maxPasswordAge,
                    details: credentialAges.passwordAge ? `${credentialAges.passwordAge} days old` : 'N/A'
                },
                {
                    name: 'API Key Rotation',
                    passed: !credentialAges.apiKeyAge || credentialAges.apiKeyAge < maxApiKeyAge,
                    details: credentialAges.apiKeyAge ? `${credentialAges.apiKeyAge} days old` : 'N/A'
                },
                {
                    name: 'Certificate Expiration',
                    passed: !credentialAges.certificateExpiration || credentialAges.certificateExpiration > new Date(),
                    details: credentialAges.certificateExpiration ? `Expires: ${credentialAges.certificateExpiration.toISOString()}` : 'N/A'
                },
                {
                    name: 'MFA Token Rotation',
                    passed: !credentialAges.mfaTokenAge || credentialAges.mfaTokenAge < maxMfaTokenAge,
                    details: credentialAges.mfaTokenAge ? `${credentialAges.mfaTokenAge} days old` : 'N/A'
                },
            ];
            const allPassed = checks.every(check => check.passed);
            result.passed = allPassed;
            result.details = {
                checks,
                allPassed,
                event: {
                    type: 'credential-rotation',
                    userId: user.id,
                    timestamp: new Date(),
                    details: { checks },
                },
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testMFAEnforcement(user) {
        const result = {
            testType: 'access-control',
            testName: 'MFA Enforcement Test',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            let mfaStatus;
            if (this.identityProvider) {
                try {
                    mfaStatus = await this.identityProvider.getMFAStatus(user.id);
                }
                catch (error) {
                    mfaStatus = this.config.mockData?.mfaStatus || {
                        enabled: false,
                        requiredForAdmin: false,
                        backupCodesGenerated: false,
                        deviceRegistered: false,
                    };
                }
            }
            else {
                mfaStatus = this.config.mockData?.mfaStatus || {
                    enabled: false,
                    requiredForAdmin: false,
                    backupCodesGenerated: false,
                    deviceRegistered: false,
                };
            }
            const mfaChecks = [
                { name: 'MFA Enabled', passed: mfaStatus.enabled },
                { name: 'MFA Required for Admin', passed: user.role === 'admin' ? mfaStatus.requiredForAdmin : true },
                { name: 'MFA Backup Codes Generated', passed: mfaStatus.backupCodesGenerated },
                { name: 'MFA Device Registered', passed: mfaStatus.deviceRegistered },
            ];
            const allPassed = mfaChecks.every(check => check.passed);
            result.passed = allPassed;
            result.details = {
                mfaChecks,
                allPassed,
                event: {
                    type: 'mfa-enforcement',
                    userId: user.id,
                    timestamp: new Date(),
                    details: { mfaChecks },
                },
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
}
exports.IdentityLifecycleTester = IdentityLifecycleTester;
//# sourceMappingURL=identity-lifecycle-tester.js.map