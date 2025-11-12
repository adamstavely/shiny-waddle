import { ABACPolicy } from '../core/types';
import { PDPRequest, PDPDecision } from './policy-decision-point';
export interface PolicyLanguageAdapter {
    name: string;
    evaluate(request: PDPRequest, policy: any): Promise<PDPDecision>;
    convertFromABAC(abacPolicy: ABACPolicy): any;
    convertToABAC(policy: any): ABACPolicy;
    validate(policy: any): {
        valid: boolean;
        errors: string[];
    };
}
export declare class PolicyLanguageSupport {
    private adapters;
    constructor();
    registerAdapter(adapter: PolicyLanguageAdapter): void;
    getAdapter(language: string): PolicyLanguageAdapter | null;
    evaluate(language: string, request: PDPRequest, policy: any): Promise<PDPDecision>;
    convertPolicy(fromLanguage: string, toLanguage: string, policy: any): any;
    validate(language: string, policy: any): {
        valid: boolean;
        errors: string[];
    };
}
