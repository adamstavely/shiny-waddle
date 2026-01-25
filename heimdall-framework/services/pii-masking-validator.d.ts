import { PiiDetectionRule } from '../core/types';
export declare class PiiMaskingValidator {
    private detectionRules;
    constructor(detectionRules: PiiDetectionRule[]);
    detectPiiFields(fields: string[]): string[];
    private matchesRule;
    validatePiiMasking(query: string, piiFields: string[]): {
        compliant: boolean;
        unmaskedFields: string[];
    };
    validateResponseMasking(data: any, piiFields: string[]): {
        compliant: boolean;
        unmaskedFields: string[];
        sampleValues: Record<string, any>;
    };
    private isMasked;
    private getNestedValue;
}
