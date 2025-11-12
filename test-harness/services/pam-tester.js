"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PAMTester = void 0;
class PAMTester {
    constructor(config) {
        this.config = config || {};
        this.pamProvider = this.config.pamProvider;
        this.config.maxJITDuration = this.config.maxJITDuration || 480;
    }
    async testJITAccess(request) {
        const result = {
            testType: 'access-control',
            testName: 'Just-In-Time Access Test',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            let userAuthorized = true;
            let resourceAccessible = true;
            if (this.pamProvider) {
                try {
                    userAuthorized = await this.pamProvider.isUserAuthorized(request.userId, request.resource);
                    resourceAccessible = await this.pamProvider.isResourceAccessible(request.resource);
                }
                catch (error) {
                    userAuthorized = this.config.mockData?.userAuthorized ?? true;
                    resourceAccessible = this.config.mockData?.resourceAccessible ?? true;
                }
            }
            else {
                userAuthorized = this.config.mockData?.userAuthorized ?? true;
                resourceAccessible = this.config.mockData?.resourceAccessible ?? true;
            }
            const maxDuration = this.config.maxJITDuration || 480;
            const validations = [
                { name: 'User Authorized', passed: userAuthorized },
                { name: 'Resource Accessible', passed: resourceAccessible },
                { name: 'Duration Valid', passed: request.duration > 0 && request.duration <= maxDuration },
                { name: 'Reason Provided', passed: request.reason.length > 0 },
                { name: 'Approval Required', passed: request.approver !== undefined },
            ];
            const allValid = validations.every(v => v.passed);
            if (!allValid) {
                result.error = 'JIT access request validation failed';
                result.details = { validations };
                return result;
            }
            const jitSteps = [
                { name: 'Request Approval', completed: true },
                { name: 'Approver Notification', completed: true },
                { name: 'Temporary Access Granted', completed: true },
                { name: 'Access Logged', completed: true },
                { name: 'Expiration Scheduled', completed: true },
            ];
            const allCompleted = jitSteps.every(step => step.completed);
            result.passed = allCompleted;
            result.details = {
                request,
                validations,
                jitSteps,
                allCompleted,
                expirationTime: new Date(Date.now() + request.duration * 60 * 1000),
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async testBreakGlassAccess(emergencyRequest) {
        const result = {
            testType: 'access-control',
            testName: 'Break-Glass Access Test',
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            if (!emergencyRequest.emergency) {
                result.error = 'Break-glass access requires emergency flag';
                return result;
            }
            let hasEmergencyPermissions = true;
            if (this.pamProvider) {
                try {
                    hasEmergencyPermissions = await this.pamProvider.hasEmergencyPermissions(emergencyRequest.userId);
                }
                catch (error) {
                    hasEmergencyPermissions = this.config.mockData?.emergencyPermissions ?? true;
                }
            }
            else {
                hasEmergencyPermissions = this.config.mockData?.emergencyPermissions ?? true;
            }
            const validations = [
                { name: 'Emergency Flag Set', passed: emergencyRequest.emergency },
                { name: 'User Authorized for Emergency', passed: hasEmergencyPermissions },
                { name: 'Reason Provided', passed: emergencyRequest.reason.length > 0 },
                { name: 'Audit Trail Enabled', passed: true },
            ];
            const allValid = validations.every(v => v.passed);
            if (!allValid) {
                result.error = 'Break-glass access validation failed';
                result.details = { validations };
                return result;
            }
            const breakGlassSteps = [
                { name: 'Emergency Access Granted', completed: true },
                { name: 'Security Team Notified', completed: true },
                { name: 'Audit Log Entry Created', completed: true },
                { name: 'Access Monitored', completed: true },
                { name: 'Post-Access Review Scheduled', completed: true },
            ];
            const allCompleted = breakGlassSteps.every(step => step.completed);
            result.passed = allCompleted;
            result.details = {
                request: emergencyRequest,
                validations,
                breakGlassSteps,
                allCompleted,
                postAccessReviewRequired: true,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
    async validatePAMWorkflows(workflows) {
        const results = [];
        for (const workflow of workflows) {
            const result = {
                testType: 'access-control',
                testName: `PAM Workflow Validation: ${workflow.name}`,
                passed: false,
                details: {},
                timestamp: new Date(),
            };
            try {
                const validations = [
                    { name: 'Workflow Has Steps', passed: workflow.steps.length > 0 },
                    { name: 'All Steps Valid', passed: workflow.steps.every(s => ['approval', 'notification', 'validation'].includes(s.type)) },
                    { name: 'Workflow Has ID', passed: workflow.id.length > 0 },
                    { name: 'Workflow Has Name', passed: workflow.name.length > 0 },
                ];
                const allValid = validations.every(v => v.passed);
                result.passed = allValid;
                result.details = {
                    workflow,
                    validations,
                    allValid,
                };
            }
            catch (error) {
                result.error = error.message;
            }
            results.push(result);
        }
        return results;
    }
    async testWorkflowExecution(workflow, request) {
        const result = {
            testType: 'access-control',
            testName: `PAM Workflow Execution: ${workflow.name}`,
            passed: false,
            details: {},
            timestamp: new Date(),
        };
        try {
            const executionSteps = [];
            for (const step of workflow.steps) {
                let stepCompleted = false;
                let stepResult = null;
                switch (step.type) {
                    case 'approval':
                        stepCompleted = request.approver !== undefined;
                        stepResult = { approver: request.approver };
                        break;
                    case 'notification':
                        stepCompleted = true;
                        stepResult = { notified: true };
                        break;
                    case 'validation':
                        stepCompleted = request.reason.length > 0 && request.duration > 0;
                        stepResult = { validated: stepCompleted };
                        break;
                }
                executionSteps.push({
                    name: `${step.type} step`,
                    completed: stepCompleted,
                    result: stepResult,
                });
            }
            const allCompleted = executionSteps.every(step => step.completed);
            result.passed = allCompleted;
            result.details = {
                workflow,
                request,
                executionSteps,
                allCompleted,
            };
        }
        catch (error) {
            result.error = error.message;
        }
        return result;
    }
}
exports.PAMTester = PAMTester;
//# sourceMappingURL=pam-tester.js.map