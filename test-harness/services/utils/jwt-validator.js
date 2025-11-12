"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeJWT = decodeJWT;
exports.isJWTExpired = isJWTExpired;
exports.isJWTMalformed = isJWTMalformed;
exports.extractJWTClaims = extractJWTClaims;
exports.hasWeakAlgorithm = hasWeakAlgorithm;
exports.hasNoExpiration = hasNoExpiration;
exports.hasLongExpiration = hasLongExpiration;
exports.analyzeJWTSecurity = analyzeJWTSecurity;
function decodeJWT(token) {
    const result = {
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
        const headerJson = Buffer.from(parts[0], 'base64url').toString('utf-8');
        result.header = JSON.parse(headerJson);
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf-8');
        result.payload = JSON.parse(payloadJson);
        result.claims = {
            issuer: result.payload.iss,
            subject: result.payload.sub,
            audience: result.payload.aud,
            expiration: result.payload.exp ? new Date(result.payload.exp * 1000) : undefined,
            issuedAt: result.payload.iat ? new Date(result.payload.iat * 1000) : undefined,
            notBefore: result.payload.nbf ? new Date(result.payload.nbf * 1000) : undefined,
        };
        if (result.payload.exp) {
            const expirationDate = new Date(result.payload.exp * 1000);
            result.expired = expirationDate < new Date();
        }
        result.valid = !result.malformed;
    }
    catch (error) {
        result.malformed = true;
        result.error = error.message || 'Failed to decode JWT';
    }
    return result;
}
function isJWTExpired(token) {
    const decoded = decodeJWT(token);
    return decoded.expired || false;
}
function isJWTMalformed(token) {
    const decoded = decodeJWT(token);
    return decoded.malformed || false;
}
function extractJWTClaims(token) {
    const decoded = decodeJWT(token);
    return decoded.payload || null;
}
function hasWeakAlgorithm(token) {
    const decoded = decodeJWT(token);
    if (!decoded.header) {
        return false;
    }
    const alg = decoded.header.alg;
    if (!alg) {
        return true;
    }
    if (alg.toLowerCase() === 'none') {
        return true;
    }
    const weakAlgorithms = ['HS256', 'HS384', 'HS512'];
    return false;
}
function hasNoExpiration(token) {
    const decoded = decodeJWT(token);
    return decoded.payload ? !decoded.payload.exp : false;
}
function hasLongExpiration(token, maxDays = 365) {
    const decoded = decodeJWT(token);
    if (!decoded.payload || !decoded.payload.exp || !decoded.payload.iat) {
        return false;
    }
    const expirationDate = new Date(decoded.payload.exp * 1000);
    const issuedDate = new Date(decoded.payload.iat * 1000);
    const daysUntilExpiration = (expirationDate.getTime() - issuedDate.getTime()) / (1000 * 60 * 60 * 24);
    return daysUntilExpiration > maxDays;
}
function analyzeJWTSecurity(token) {
    const issues = [];
    const warnings = [];
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
    }
    else if (hasLongExpiration(token)) {
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
//# sourceMappingURL=jwt-validator.js.map