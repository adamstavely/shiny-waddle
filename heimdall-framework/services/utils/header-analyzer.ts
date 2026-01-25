/**
 * Security Header Analyzer
 * Functions for analyzing and validating HTTP security headers
 */

export interface SecurityHeaderAnalysis {
  header: string;
  present: boolean;
  value?: string;
  valid: boolean;
  issues: string[];
  recommendations: string[];
}

export interface SecurityHeadersReport {
  overallScore: number; // 0-100
  headers: SecurityHeaderAnalysis[];
  criticalIssues: string[];
  warnings: string[];
}

/**
 * Required security headers and their expected values/patterns
 */
const SECURITY_HEADERS = {
  'strict-transport-security': {
    required: true,
    pattern: /^max-age=\d+/i,
    recommended: 'max-age=31536000; includeSubDomains; preload',
    description: 'HSTS - Forces HTTPS connections',
  },
  'x-content-type-options': {
    required: true,
    pattern: /^nosniff$/i,
    recommended: 'nosniff',
    description: 'Prevents MIME type sniffing',
  },
  'x-frame-options': {
    required: true,
    pattern: /^(DENY|SAMEORIGIN|ALLOW-FROM)/i,
    recommended: 'DENY',
    description: 'Prevents clickjacking attacks',
  },
  'x-xss-protection': {
    required: false, // Deprecated but still checked
    pattern: /^1; mode=block$/i,
    recommended: '1; mode=block',
    description: 'XSS protection (deprecated, use CSP instead)',
  },
  'content-security-policy': {
    required: true,
    pattern: /./, // Any CSP is better than none
    recommended: "default-src 'self'; script-src 'self'; object-src 'none';",
    description: 'Content Security Policy',
  },
  'referrer-policy': {
    required: true,
    pattern: /^(no-referrer|no-referrer-when-downgrade|origin|origin-when-cross-origin|same-origin|strict-origin|strict-origin-when-cross-origin|unsafe-url)$/i,
    recommended: 'strict-origin-when-cross-origin',
    description: 'Controls referrer information',
  },
  'permissions-policy': {
    required: false,
    pattern: /./,
    recommended: "geolocation=(), microphone=(), camera=()",
    description: 'Feature Policy (formerly Permissions Policy)',
  },
  'x-permitted-cross-domain-policies': {
    required: false,
    pattern: /^(none|master-only|by-content-type|all)$/i,
    recommended: 'none',
    description: 'Cross-domain policy',
  },
};

/**
 * Analyze a single security header
 */
export function analyzeSecurityHeader(
  headerName: string,
  headerValue: string | null
): SecurityHeaderAnalysis {
  const headerNameLower = headerName.toLowerCase();
  const headerConfig = SECURITY_HEADERS[headerNameLower as keyof typeof SECURITY_HEADERS];
  
  const analysis: SecurityHeaderAnalysis = {
    header: headerName,
    present: headerValue !== null && headerValue !== undefined,
    value: headerValue || undefined,
    valid: false,
    issues: [],
    recommendations: [],
  };

  if (!headerConfig) {
    // Unknown header - check for information disclosure
    if (headerNameLower.includes('server') || headerNameLower.includes('powered-by')) {
      analysis.issues.push('Server information disclosure');
      analysis.recommendations.push('Remove or obfuscate server information headers');
    }
    return analysis;
  }

  if (!analysis.present) {
    if (headerConfig.required) {
      analysis.issues.push(`Missing required security header: ${headerName}`);
      analysis.recommendations.push(`Add ${headerName} header with value: ${headerConfig.recommended}`);
    } else {
      analysis.recommendations.push(`Consider adding ${headerName} header: ${headerConfig.recommended}`);
    }
    return analysis;
  }

  // Validate header value
  if (headerConfig.pattern && !headerConfig.pattern.test(headerValue!)) {
    analysis.issues.push(`Invalid ${headerName} value: ${headerValue}`);
    analysis.recommendations.push(`Use recommended value: ${headerConfig.recommended}`);
  } else {
    analysis.valid = true;
  }

  // Specific validations
  if (headerNameLower === 'strict-transport-security') {
    if (!headerValue!.includes('max-age')) {
      analysis.issues.push('HSTS missing max-age directive');
    }
    if (!headerValue!.includes('includeSubDomains')) {
      analysis.recommendations.push('Consider adding includeSubDomains to HSTS');
    }
  }

  if (headerNameLower === 'content-security-policy') {
    if (headerValue!.includes("'unsafe-inline'")) {
      analysis.issues.push('CSP allows unsafe-inline (XSS risk)');
    }
    if (headerValue!.includes("'unsafe-eval'")) {
      analysis.issues.push('CSP allows unsafe-eval (XSS risk)');
    }
    if (!headerValue!.includes("default-src")) {
      analysis.recommendations.push('CSP should include default-src directive');
    }
  }

  if (headerNameLower === 'x-frame-options') {
    if (headerValue!.toUpperCase() !== 'DENY' && !headerValue!.toUpperCase().startsWith('SAMEORIGIN')) {
      analysis.issues.push('X-Frame-Options should be DENY or SAMEORIGIN');
    }
  }

  if (headerNameLower === 'referrer-policy') {
    if (headerValue!.toLowerCase() === 'unsafe-url') {
      analysis.issues.push('Referrer-Policy unsafe-url leaks full URLs');
    }
  }

  return analysis;
}

/**
 * Analyze CORS headers
 */
export function analyzeCORS(headers: Record<string, string>): SecurityHeaderAnalysis {
  const analysis: SecurityHeaderAnalysis = {
    header: 'CORS',
    present: false,
    valid: false,
    issues: [],
    recommendations: [],
  };

  const corsOrigin = headers['access-control-allow-origin'];
  const corsCredentials = headers['access-control-allow-credentials'];
  const corsMethods = headers['access-control-allow-methods'];

  if (corsOrigin) {
    analysis.present = true;
    analysis.value = corsOrigin;

    if (corsOrigin === '*') {
      if (corsCredentials === 'true') {
        analysis.issues.push('CORS allows all origins (*) with credentials (CRITICAL)');
        analysis.valid = false;
      } else {
        analysis.issues.push('CORS allows all origins (*)');
        analysis.recommendations.push('Specify allowed origins explicitly');
        analysis.valid = false;
      }
    } else {
      analysis.valid = true;
    }

    if (corsMethods && corsMethods.includes('*')) {
      analysis.issues.push('CORS allows all HTTP methods');
      analysis.recommendations.push('Specify allowed methods explicitly');
    }
  } else {
    analysis.recommendations.push('Consider implementing CORS if API is accessed from browsers');
  }

  return analysis;
}

/**
 * Analyze all security headers from response
 */
export function analyzeSecurityHeaders(headers: Record<string, string>): SecurityHeadersReport {
  const headerAnalyses: SecurityHeaderAnalysis[] = [];
  const criticalIssues: string[] = [];
  const warnings: string[] = [];
  let score = 100;

  // Analyze standard security headers
  for (const [headerName, headerConfig] of Object.entries(SECURITY_HEADERS)) {
    const headerValue = headers[headerName] || headers[headerName.toLowerCase()] || null;
    const analysis = analyzeSecurityHeader(headerName, headerValue);
    headerAnalyses.push(analysis);

    if (analysis.issues.length > 0) {
      if (headerConfig.required) {
        criticalIssues.push(...analysis.issues);
        score -= 15;
      } else {
        warnings.push(...analysis.issues);
        score -= 5;
      }
    }
  }

  // Analyze CORS
  const corsAnalysis = analyzeCORS(headers);
  headerAnalyses.push(corsAnalysis);
  if (corsAnalysis.issues.length > 0) {
    if (corsAnalysis.issues.some(i => i.includes('CRITICAL'))) {
      criticalIssues.push(...corsAnalysis.issues);
      score -= 20;
    } else {
      warnings.push(...corsAnalysis.issues);
      score -= 10;
    }
  }

  // Check for information disclosure headers
  const disclosureHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime'];
  for (const header of disclosureHeaders) {
    if (headers[header] || headers[header.toLowerCase()]) {
      warnings.push(`Server information disclosure: ${header} header present`);
      score -= 5;
    }
  }

  return {
    overallScore: Math.max(0, score),
    headers: headerAnalyses,
    criticalIssues,
    warnings,
  };
}

