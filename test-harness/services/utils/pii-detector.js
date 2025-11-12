"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectPII = detectPII;
exports.detectPIIInJSON = detectPIIInJSON;
exports.containsSensitivePII = containsSensitivePII;
const PII_PATTERNS = [
    {
        type: 'SSN',
        pattern: /\b\d{3}-?\d{2}-?\d{4}\b/g,
        severity: 'critical',
        description: 'US Social Security Number',
    },
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
    {
        type: 'Email',
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        severity: 'high',
        description: 'Email Address',
    },
    {
        type: 'PhoneUS',
        pattern: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
        severity: 'high',
        description: 'US Phone Number',
    },
    {
        type: 'IPAddress',
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        severity: 'medium',
        description: 'IP Address',
    },
    {
        type: 'PotentialBirthDate',
        pattern: /\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])\b/g,
        severity: 'medium',
        description: 'Potential Birth Date',
    },
    {
        type: 'DriversLicense',
        pattern: /\b[A-Z0-9]{6,12}\b/g,
        severity: 'high',
        description: 'Potential Driver\'s License Number',
    },
    {
        type: 'Passport',
        pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
        severity: 'critical',
        description: 'Potential Passport Number',
    },
    {
        type: 'BankAccount',
        pattern: /\b\d{8,17}\b/g,
        severity: 'critical',
        description: 'Potential Bank Account Number',
    },
    {
        type: 'MedicalRecord',
        pattern: /\bMRN[-:]?\s*\d{6,12}\b/gi,
        severity: 'critical',
        description: 'Medical Record Number',
    },
    {
        type: 'HealthInsurance',
        pattern: /\bHI[-:]?\s*\d{6,12}\b/gi,
        severity: 'critical',
        description: 'Health Insurance Number',
    },
];
function detectPII(content) {
    const matches = [];
    const piiTypes = new Set();
    let maxSeverity = 'none';
    for (const pattern of PII_PATTERNS) {
        const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
        const found = content.match(regex);
        if (found) {
            piiTypes.add(pattern.type);
            if (pattern.severity === 'critical' && maxSeverity !== 'critical') {
                maxSeverity = 'critical';
            }
            else if (pattern.severity === 'high' && maxSeverity !== 'critical' && maxSeverity !== 'high') {
                maxSeverity = 'high';
            }
            else if (pattern.severity === 'medium' && maxSeverity !== 'critical' && maxSeverity !== 'high' && maxSeverity !== 'medium') {
                maxSeverity = 'medium';
            }
            else if (pattern.severity === 'low' && maxSeverity === 'none') {
                maxSeverity = 'low';
            }
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
function detectPIIInJSON(json, maxDepth = 5) {
    const jsonString = JSON.stringify(json, null, 2);
    return detectPII(jsonString);
}
function containsSensitivePII(content) {
    const result = detectPII(content);
    return result.severity === 'critical' || result.severity === 'high';
}
//# sourceMappingURL=pii-detector.js.map