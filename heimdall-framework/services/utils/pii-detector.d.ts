export interface PIIDetection {
    type: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
}
export interface PIIDetectionResult {
    detected: boolean;
    piiTypes: string[];
    matches: Array<{
        type: string;
        value: string;
        severity: string;
        position?: number;
    }>;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
}
export declare function detectPII(content: string): PIIDetectionResult;
export declare function detectPIIInJSON(json: any, maxDepth?: number): PIIDetectionResult;
export declare function containsSensitivePII(content: string): boolean;
