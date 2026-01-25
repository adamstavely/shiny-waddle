/**
 * JWT Validator Utility
 * Functions for parsing, validating, and analyzing JWT tokens
 */

export interface JWTPayload {
  [key: string]: any;
  iss?: string; // Issuer
  sub?: string; // Subject
  aud?: string | string[]; // Audience
  exp?: number; // Expiration time
  nbf?: number; // Not before
  iat?: number; // Issued at
  jti?: string; // JWT ID
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

/**
 * Decode JWT without verification (for testing purposes)
 * Note: In production, always verify signatures!
 */
export function decodeJWT(token: string): JWTValidationResult {
  const result: JWTValidationResult = {
    valid: false,
    expired: false,
    malformed: false,
  };

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      result.malformed = true;
      result.error = 'JWT must have 3 parts separated by dots';
      return result;
    }

    // Decode header
    const headerJson = Buffer.from(parts[0], 'base64url').toString('utf-8');
    result.header = JSON.parse(headerJson);

    // Decode payload
    const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf-8');
    result.payload = JSON.parse(payloadJson);

    // Extract claims
    result.claims = {
      issuer: result.payload.iss,
      subject: result.payload.sub,
      audience: result.payload.aud,
      expiration: result.payload.exp ? new Date(result.payload.exp * 1000) : undefined,
      issuedAt: result.payload.iat ? new Date(result.payload.iat * 1000) : undefined,
      notBefore: result.payload.nbf ? new Date(result.payload.nbf * 1000) : undefined,
    };

    // Check expiration
    if (result.payload.exp) {
      const expirationDate = new Date(result.payload.exp * 1000);
      result.expired = expirationDate < new Date();
    }

    result.valid = !result.malformed;
  } catch (error: any) {
    result.malformed = true;
    result.error = error.message || 'Failed to decode JWT';
  }

  return result;
}

/**
 * Check if JWT is expired
 */
export function isJWTExpired(token: string): boolean {
  const decoded = decodeJWT(token);
  return decoded.expired || false;
}

/**
 * Check if JWT is malformed
 */
export function isJWTMalformed(token: string): boolean {
  const decoded = decodeJWT(token);
  return decoded.malformed || false;
}

/**
 * Extract claims from JWT
 */
export function extractJWTClaims(token: string): JWTPayload | null {
  const decoded = decodeJWT(token);
  return decoded.payload || null;
}

/**
 * Check if JWT has weak algorithm (none, HS256 with weak key, etc.)
 */
export function hasWeakAlgorithm(token: string): boolean {
  const decoded = decodeJWT(token);
  if (!decoded.header) {
    return false;
  }

  const alg = decoded.header.alg;
  if (!alg) {
    return true; // Missing algorithm is weak
  }

  // Check for 'none' algorithm (no signature)
  if (alg.toLowerCase() === 'none') {
    return true;
  }

  // Check for weak algorithms
  const weakAlgorithms = ['HS256', 'HS384', 'HS512']; // Can be weak if key is weak
  // Note: In practice, we'd need to verify the signature to determine if key is weak
  // For testing purposes, we'll flag if algorithm is missing or 'none'

  return false;
}

/**
 * Check if JWT has no expiration
 */
export function hasNoExpiration(token: string): boolean {
  const decoded = decodeJWT(token);
  return decoded.payload ? !decoded.payload.exp : false;
}

/**
 * Check if JWT has very long expiration (potential security issue)
 */
export function hasLongExpiration(token: string, maxDays: number = 365): boolean {
  const decoded = decodeJWT(token);
  if (!decoded.payload || !decoded.payload.exp || !decoded.payload.iat) {
    return false;
  }

  const expirationDate = new Date(decoded.payload.exp * 1000);
  const issuedDate = new Date(decoded.payload.iat * 1000);
  const daysUntilExpiration = (expirationDate.getTime() - issuedDate.getTime()) / (1000 * 60 * 60 * 24);

  return daysUntilExpiration > maxDays;
}

/**
 * Analyze JWT for security issues
 */
export function analyzeJWTSecurity(token: string): {
  issues: string[];
  warnings: string[];
  score: number; // 0-100, higher is better
} {
  const issues: string[] = [];
  const warnings: string[] = [];
  let score = 100;

  const decoded = decodeJWT(token);

  if (decoded.malformed) {
    issues.push('JWT is malformed');
    score -= 50;
    return { issues, warnings, score };
  }

  if (decoded.expired) {
    warnings.push('JWT is expired');
    score -= 10;
  }

  if (hasWeakAlgorithm(token)) {
    issues.push('JWT uses weak or missing algorithm');
    score -= 30;
  }

  if (hasNoExpiration(token)) {
    issues.push('JWT has no expiration time');
    score -= 20;
  } else if (hasLongExpiration(token)) {
    warnings.push('JWT has very long expiration time');
    score -= 10;
  }

  if (!decoded.payload?.iss) {
    warnings.push('JWT missing issuer claim');
    score -= 5;
  }

  if (!decoded.payload?.sub) {
    warnings.push('JWT missing subject claim');
    score -= 5;
  }

  return {
    issues,
    warnings,
    score: Math.max(0, score),
  };
}

