/**
 * PII (Personally Identifiable Information) Detector
 * Functions for detecting PII patterns in API responses
 */

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

/**
 * Common PII patterns
 */
const PII_PATTERNS: PIIDetection[] = [
  // Social Security Number (US)
  {
    type: 'SSN',
    pattern: /\b\d{3}-?\d{2}-?\d{4}\b/g,
    severity: 'critical',
    description: 'US Social Security Number',
  },
  
  // Credit Card Numbers
  {
    type: 'CreditCard',
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    severity: 'critical',
    description: 'Credit Card Number',
  },
  {
    type: 'CreditCardVisa',
    pattern: /\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    severity: 'critical',
    description: 'Visa Credit Card',
  },
  {
    type: 'CreditCardMastercard',
    pattern: /\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    severity: 'critical',
    description: 'Mastercard Credit Card',
  },
  
  // Email addresses
  {
    type: 'Email',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    severity: 'high',
    description: 'Email Address',
  },
  
  // Phone numbers (US)
  {
    type: 'PhoneUS',
    pattern: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    severity: 'high',
    description: 'US Phone Number',
  },
  
  // IP addresses (may be sensitive in some contexts)
  {
    type: 'IPAddress',
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    severity: 'medium',
    description: 'IP Address',
  },
  
  // Dates that might indicate birth dates (YYYY-MM-DD or MM/DD/YYYY)
  {
    type: 'PotentialBirthDate',
    pattern: /\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])\b/g,
    severity: 'medium',
    description: 'Potential Birth Date',
  },
  
  // Driver's License (US - varies by state, generic pattern)
  {
    type: 'DriversLicense',
    pattern: /\b[A-Z0-9]{6,12}\b/g,
    severity: 'high',
    description: 'Potential Driver\'s License Number',
  },
  
  // Passport numbers (varies by country)
  {
    type: 'Passport',
    pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
    severity: 'critical',
    description: 'Potential Passport Number',
  },
  
  // Bank Account Numbers (generic - varies by country)
  {
    type: 'BankAccount',
    pattern: /\b\d{8,17}\b/g,
    severity: 'critical',
    description: 'Potential Bank Account Number',
  },
  
  // Medical Record Numbers
  {
    type: 'MedicalRecord',
    pattern: /\bMRN[-:]?\s*\d{6,12}\b/gi,
    severity: 'critical',
    description: 'Medical Record Number',
  },
  
  // Health Insurance Numbers
  {
    type: 'HealthInsurance',
    pattern: /\bHI[-:]?\s*\d{6,12}\b/gi,
    severity: 'critical',
    description: 'Health Insurance Number',
  },
];

/**
 * Detect PII in text content
 */
export function detectPII(content: string): PIIDetectionResult {
  const matches: PIIDetectionResult['matches'] = [];
  const piiTypes = new Set<string>();
  let maxSeverity: PIIDetectionResult['severity'] = 'none';

  for (const pattern of PII_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    const found = content.match(regex);
    
    if (found) {
      piiTypes.add(pattern.type);
      
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

      // Add matches (limit to first 10 per type to avoid overwhelming output)
      for (let i = 0; i < Math.min(found.length, 10); i++) {
        matches.push({
          type: pattern.type,
          value: found[i],
          severity: pattern.severity,
          position: content.indexOf(found[i]),
        });
      }
    }
  }

  return {
    detected: matches.length > 0,
    piiTypes: Array.from(piiTypes),
    matches,
    severity: maxSeverity,
  };
}

/**
 * Detect PII in JSON response
 */
export function detectPIIInJSON(json: any, maxDepth: number = 5): PIIDetectionResult {
  const jsonString = JSON.stringify(json, null, 2);
  return detectPII(jsonString);
}

/**
 * Check if response contains sensitive PII
 */
export function containsSensitivePII(content: string): boolean {
  const result = detectPII(content);
  return result.severity === 'critical' || result.severity === 'high';
}

