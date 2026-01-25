export interface JWTPayload {
    [key: string]: any;
    iss?: string;
    sub?: string;
    aud?: string | string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
}
export interface JWTValidationResult {
    valid: boolean;
    expired: boolean;
    malformed: boolean;
    payload?: JWTPayload;
    header?: Record<string, any>;
    error?: string;
    claims?: {
        issuer?: string;
        subject?: string;
        audience?: string | string[];
        expiration?: Date;
        issuedAt?: Date;
        notBefore?: Date;
    };
}
export declare function decodeJWT(token: string): JWTValidationResult;
export declare function isJWTExpired(token: string): boolean;
export declare function isJWTMalformed(token: string): boolean;
export declare function extractJWTClaims(token: string): JWTPayload | null;
export declare function hasWeakAlgorithm(token: string): boolean;
export declare function hasNoExpiration(token: string): boolean;
export declare function hasLongExpiration(token: string, maxDays?: number): boolean;
export declare function analyzeJWTSecurity(token: string): {
    issues: string[];
    warnings: string[];
    score: number;
};
