export interface CredentialPattern {
    type: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
}
export interface CredentialDetectionResult {
    detected: boolean;
    credentialTypes: string[];
    matches: Array<{
        type: string;
        value: string;
        severity: string;
        position?: number;
    }>;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
}
export declare function detectCredentials(content: string): CredentialDetectionResult;
export declare function detectCredentialsInJSON(json: any): CredentialDetectionResult;
export declare function containsExposedCredentials(content: string): boolean;
