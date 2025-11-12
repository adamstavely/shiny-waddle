"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DataBehaviorTester = void 0;
const query_analyzer_1 = require("./query-analyzer");
const pii_masking_validator_1 = require("./pii-masking-validator");
class DataBehaviorTester {
    constructor(config) {
        this.config = config;
        this.queryAnalyzer = new query_analyzer_1.QueryAnalyzer(config);
        this.piiValidator = new pii_masking_validator_1.PiiMaskingValidator(config.piiDetectionRules || []);
    }
    async testQuery(input) {
        const violations = [];
        const recommendations = [];
        const analysis = await this.queryAnalyzer.analyze(input.query);
        if (this.isOverBroadQuery(analysis, input.user)) {
            violations.push('Over-broad query: Query may return more data than user role permits');
        }
        if (input.requiredFilters) {
            const missingFilters = this.findMissingFilters(analysis.filtersApplied, input.requiredFilters);
            if (missingFilters.length > 0) {
                violations.push(`Missing required filters: ${missingFilters.map(f => f.field).join(', ')}`);
            }
        }
        if (input.expectedFields) {
            const disallowedFields = analysis.fieldsUsed.filter(field => !input.expectedFields.includes(field));
            if (disallowedFields.length > 0) {
                violations.push(`Disallowed fields accessed: ${disallowedFields.join(', ')}`);
            }
        }
        if (input.disallowedJoins) {
            const disallowedJoinsFound = analysis.joinsUsed.filter(join => input.disallowedJoins.some(disallowed => join.includes(disallowed)));
            if (disallowedJoinsFound.length > 0) {
                violations.push(`Disallowed joins detected: ${disallowedJoinsFound.join(', ')}`);
            }
        }
        const piiFields = this.piiValidator.detectPiiFields(analysis.fieldsUsed);
        if (piiFields.length > 0 && !this.isPiiMasked(analysis, piiFields)) {
            violations.push(`PII fields exposed without masking: ${piiFields.join(', ')}`);
        }
        if (input.user.role === 'viewer' || input.user.role === 'analyst') {
            if (analysis.aggregationsApplied.length === 0 && analysis.fieldsUsed.length > 0) {
                recommendations.push('Consider applying aggregations to protect individual records (k-anonymity)');
            }
        }
        return {
            compliant: violations.length === 0,
            violations,
            queryAnalysis: {
                fieldsUsed: analysis.fieldsUsed,
                joinsUsed: analysis.joinsUsed,
                filtersApplied: analysis.filtersApplied,
                aggregationsApplied: analysis.aggregationsApplied,
                piiFieldsExposed: piiFields,
            },
            recommendations,
        };
    }
    isOverBroadQuery(analysis, user) {
        if ((user.role === 'viewer' || user.role === 'analyst') && analysis.aggregationsApplied.length === 0) {
            if (!analysis.hasLimit || (analysis.limit && analysis.limit > 1000)) {
                return true;
            }
        }
        return false;
    }
    findMissingFilters(appliedFilters, requiredFilters) {
        return requiredFilters.filter(required => {
            return !appliedFilters.some(applied => applied.field === required.field &&
                applied.operator === required.operator &&
                this.filterValuesMatch(applied.value, required.value));
        });
    }
    filterValuesMatch(value1, value2) {
        if (Array.isArray(value1) && Array.isArray(value2)) {
            return value1.every(v => value2.includes(v));
        }
        return value1 === value2;
    }
    isPiiMasked(analysis, piiFields) {
        return piiFields.every(field => {
            return analysis.fieldsUsed.some((usedField) => {
                return (usedField.includes(`MASK(${field})`) ||
                    usedField.includes(`HASH(${field})`) ||
                    usedField.includes(`REDACT(${field})`));
            });
        });
    }
}
exports.DataBehaviorTester = DataBehaviorTester;
//# sourceMappingURL=data-behavior-tester.js.map