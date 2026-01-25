/**
 * Credential Detector
 * Functions for detecting exposed credentials, API keys, tokens, etc.
 */

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

/**
 * Common credential patterns
 */
const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // API Keys
  {
    type: 'AWS_ACCESS_KEY',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    description: 'AWS Access Key ID',
  },
  {
    type: 'AWS_SECRET_KEY',
    pattern: /\b[A-Za-z0-9/+=]{40}\b/g,
    severity: 'critical',
    description: 'AWS Secret Access Key (potential)',
  },
  {
    type: 'GoogleAPIKey',
    pattern: /\bAIza[0-9A-Za-z-_]{35}\b/g,
    severity: 'critical',
    description: 'Google API Key',
  },
  {
    type: 'GitHubToken',
    pattern: /\bghp_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token',
  },
  {
    type: 'GitHubOAuth',
    pattern: /\bgho_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub OAuth Token',
  },
  {
    type: 'SlackToken',
    pattern: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g,
    severity: 'critical',
    description: 'Slack Token',
  },
  {
    type: 'StripeKey',
    pattern: /\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b/g,
    severity: 'critical',
    description: 'Stripe API Key',
  },
  {
    type: 'TwilioKey',
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    severity: 'critical',
    description: 'Twilio API Key',
  },
  {
    type: 'GenericAPIKey',
    pattern: /\b(api[_-]?key|apikey|api-key)[\s:=]+['"]?([A-Za-z0-9_-]{20,})['"]?/gi,
    severity: 'high',
    description: 'Generic API Key Pattern',
  },
  
  // Tokens
  {
    type: 'JWT',
    pattern: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g,
    severity: 'high',
    description: 'JWT Token',
  },
  {
    type: 'BearerToken',
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi,
    severity: 'high',
    description: 'Bearer Token',
  },
  
  // Passwords (in responses - should not be present)
  {
    type: 'Password',
    pattern: /\b(password|pwd|passwd)[\s:=]+['"]?([^\s'"]{8,})['"]?/gi,
    severity: 'critical',
    description: 'Password in Response',
  },
  {
    type: 'HashedPassword',
    pattern: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g,
    severity: 'high',
    description: 'Bcrypt Hashed Password',
  },
  {
    type: 'MD5Hash',
    pattern: /\b[a-f0-9]{32}\b/gi,
    severity: 'medium',
    description: 'MD5 Hash (potential password hash)',
  },
  {
    type: 'SHA1Hash',
    pattern: /\b[a-f0-9]{40}\b/gi,
    severity: 'medium',
    description: 'SHA1 Hash (potential password hash)',
  },
  
  // Database connection strings
  {
    type: 'MongoDBConnection',
    pattern: /mongodb(\+srv)?:\/\/[^\s'"]+/gi,
    severity: 'critical',
    description: 'MongoDB Connection String',
  },
  {
    type: 'PostgreSQLConnection',
    pattern: /postgres(ql)?:\/\/[^\s'"]+/gi,
    severity: 'critical',
    description: 'PostgreSQL Connection String',
  },
  {
    type: 'MySQLConnection',
    pattern: /mysql:\/\/[^\s'"]+/gi,
    severity: 'critical',
    description: 'MySQL Connection String',
  },
  {
    type: 'RedisConnection',
    pattern: /redis:\/\/[^\s'"]+/gi,
    severity: 'critical',
    description: 'Redis Connection String',
  },
  
  // OAuth tokens
  {
    type: 'OAuthToken',
    pattern: /\b(access[_-]?token|oauth[_-]?token)[\s:=]+['"]?([A-Za-z0-9\-._~+/]+=*)['"]?/gi,
    severity: 'high',
    description: 'OAuth Access Token',
  },
  {
    type: 'OAuthRefreshToken',
    pattern: /\b(refresh[_-]?token)[\s:=]+['"]?([A-Za-z0-9\-._~+/]+=*)['"]?/gi,
    severity: 'high',
    description: 'OAuth Refresh Token',
  },
  
  // Private keys
  {
    type: 'PrivateKey',
    pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----/gi,
    severity: 'critical',
    description: 'Private Key',
  },
  {
    type: 'SSHPrivateKey',
    pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/gi,
    severity: 'critical',
    description: 'SSH Private Key',
  },
  
  // Session tokens
  {
    type: 'PHPSessionID',
    pattern: /\bPHPSESSID[\s:=]+['"]?([A-Za-z0-9]{26,32})['"]?/gi,
    severity: 'high',
    description: 'PHP Session ID',
  },
  {
    type: 'SessionToken',
    pattern: /\b(session[_-]?id|session[_-]?token)[\s:=]+['"]?([A-Za-z0-9\-._~+/]+=*)['"]?/gi,
    severity: 'high',
    description: 'Session Token',
  },
];

/**
 * Detect credentials in text content
 */
export function detectCredentials(content: string): CredentialDetectionResult {
  const matches: CredentialDetectionResult['matches'] = [];
  const credentialTypes = new Set<string>();
  let maxSeverity: CredentialDetectionResult['severity'] = 'none';

  for (const pattern of CREDENTIAL_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    const found = content.match(regex);
    
    if (found) {
      credentialTypes.add(pattern.type);
      
      // Update max severity
      if (pattern.severity === 'critical' && maxSeverity !== 'critical') {
        maxSeverity = 'critical';
      } else if (pattern.severity === 'high' && maxSeverity !== 'critical' && maxSeverity !== 'high') {
        maxSeverity = 'high';
      } else if (pattern.severity === 'medium' && maxSeverity !== 'critical' && maxSeverity !== 'high' && maxSeverity !== 'medium') {
        maxSeverity = 'medium';
      } else if (pattern.severity === 'low' && maxSeverity === 'none') {
        maxSeverity = 'low';
      }

      // Add matches (limit to first 5 per type to avoid overwhelming output)
      for (let i = 0; i < Math.min(found.length, 5); i++) {
        // Mask sensitive values (show only first/last few characters)
        const value = found[i];
        let maskedValue = value;
        if (value.length > 10) {
          maskedValue = `${value.substring(0, 4)}...${value.substring(value.length - 4)}`;
        }
        
        matches.push({
          type: pattern.type,
          value: maskedValue,
          severity: pattern.severity,
          position: content.indexOf(found[i]),
        });
      }
    }
  }

  return {
    detected: matches.length > 0,
    credentialTypes: Array.from(credentialTypes),
    matches,
    severity: maxSeverity,
  };
}

/**
 * Detect credentials in JSON response
 */
export function detectCredentialsInJSON(json: any): CredentialDetectionResult {
  const jsonString = JSON.stringify(json, null, 2);
  return detectCredentials(jsonString);
}

/**
 * Check if response contains exposed credentials
 */
export function containsExposedCredentials(content: string): boolean {
  const result = detectCredentials(content);
  return result.severity === 'critical' || result.severity === 'high';
}

