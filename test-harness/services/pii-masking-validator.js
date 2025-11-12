"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PiiMaskingValidator = void 0;
class PiiMaskingValidator {
    constructor(detectionRules) {
        this.detectionRules = detectionRules;
    }
    detectPiiFields(fields) {
        const piiFields = [];
        for (const field of fields) {
            for (const rule of this.detectionRules) {
                if (this.matchesRule(field, rule)) {
                    piiFields.push(field);
                    break;
                }
            }
        }
        return piiFields;
    }
    matchesRule(field, rule) {
        if (rule.fieldPattern) {
            const pattern = new RegExp(rule.fieldPattern, 'i');
            if (!pattern.test(field)) {
                return false;
            }
        }
        if (rule.regex) {
            const regex = new RegExp(rule.regex, 'i');
            if (!regex.test(field)) {
                return false;
            }
        }
        const typePatterns = {
            email: /email|e-mail|mail/i,
            ssn: /ssn|social.*security|tax.*id/i,
            phone: /phone|mobile|tel/i,
            'credit-card': /credit.*card|card.*number|cc.*number/i,
            'ip-address': /ip.*address|ipaddr/i,
        };
        if (rule.piiType !== 'custom' && typePatterns[rule.piiType]) {
            if (typePatterns[rule.piiType].test(field)) {
                return true;
            }
        }
        return true;
    }
    validatePiiMasking(query, piiFields) {
        const unmaskedFields = [];
        for (const field of piiFields) {
            const maskingPatterns = [
                new RegExp(`MASK\\(${field}\\)`, 'i'),
                new RegExp(`HASH\\(${field}\\)`, 'i'),
                new RegExp(`REDACT\\(${field}\\)`, 'i'),
                new RegExp(`ENCRYPT\\(${field}\\)`, 'i'),
                new RegExp(`ANONYMIZE\\(${field}\\)`, 'i'),
            ];
            const isMasked = maskingPatterns.some(pattern => pattern.test(query));
            const directFieldPattern = new RegExp(`\\b${field}\\b`, 'i');
            if (directFieldPattern.test(query) && !isMasked) {
                unmaskedFields.push(field);
            }
        }
        return {
            compliant: unmaskedFields.length === 0,
            unmaskedFields,
        };
    }
    validateResponseMasking(data, piiFields) {
        const unmaskedFields = [];
        const sampleValues = {};
        for (const field of piiFields) {
            const value = this.getNestedValue(data, field);
            if (value !== undefined && !this.isMasked(value)) {
                unmaskedFields.push(field);
                sampleValues[field] = value;
            }
        }
        return {
            compliant: unmaskedFields.length === 0,
            unmaskedFields,
            sampleValues,
        };
    }
    isMasked(value) {
        if (typeof value !== 'string') {
            return false;
        }
        const maskingPatterns = [
            /^\*+$/,
            /^X+$/,
            /^[\*X]{4,}/,
            /^[a-f0-9]{32,}$/i,
            /^[a-f0-9]{64,}$/i,
        ];
        return maskingPatterns.some(pattern => pattern.test(value));
    }
    getNestedValue(obj, path) {
        const keys = path.split('.');
        let current = obj;
        for (const key of keys) {
            if (current === null || current === undefined) {
                return undefined;
            }
            current = current[key];
        }
        return current;
    }
}
exports.PiiMaskingValidator = PiiMaskingValidator;
//# sourceMappingURL=pii-masking-validator.js.map