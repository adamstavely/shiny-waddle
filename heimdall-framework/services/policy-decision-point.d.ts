import { AccessControlConfig } from '../core/types';
export interface PDPRequest {
    subject: {
        id: string;
        attributes: Record<string, any>;
    };
    resource: {
        id: string;
        type: string;
        attributes: Record<string, any>;
    };
    context: {
        ipAddress?: string;
        timeOfDay?: string;
        location?: string;
        device?: string;
        additionalAttributes?: Record<string, any>;
    };
    action?: string;
}
export interface PDPDecision {
    allowed: boolean;
    reason: string;
    appliedRules: string[];
    conditions?: Record<string, any>;
}
export declare class PolicyDecisionPoint {
    private config;
    private policyCache;
    constructor(config: AccessControlConfig);
    evaluate(request: PDPRequest): Promise<PDPDecision>;
    private evaluateWithABAC;
    private evaluateABACPolicy;
    private evaluateABACCondition;
    private resolveAttribute;
    private evaluateWithRBAC;
    private evaluateWithOPA;
    private evaluateWithCedar;
    private evaluateWithCedarAPI;
    private generateCacheKey;
    clearCache(): void;
}
