"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QueryAnalyzer = void 0;
class QueryAnalyzer {
    constructor(config) {
        this.config = config;
    }
    async analyze(query) {
        if (query.sql) {
            return this.analyzeSqlQuery(query.sql);
        }
        else if (query.apiEndpoint) {
            return this.analyzeApiRequest(query);
        }
        else {
            throw new Error('Query must have either SQL or API endpoint');
        }
    }
    analyzeSqlQuery(sql) {
        const normalizedSql = sql.toUpperCase().trim();
        const fieldsUsed = this.extractFields(normalizedSql);
        const joinsUsed = this.extractJoins(normalizedSql);
        const filtersApplied = this.extractFilters(normalizedSql);
        const aggregationsApplied = this.extractAggregations(normalizedSql);
        const limitMatch = normalizedSql.match(/LIMIT\s+(\d+)/i);
        const hasLimit = !!limitMatch;
        const limit = limitMatch ? parseInt(limitMatch[1]) : undefined;
        const hasOrderBy = /ORDER\s+BY/i.test(normalizedSql);
        let queryType = 'SELECT';
        if (/^INSERT/i.test(normalizedSql))
            queryType = 'INSERT';
        else if (/^UPDATE/i.test(normalizedSql))
            queryType = 'UPDATE';
        else if (/^DELETE/i.test(normalizedSql))
            queryType = 'DELETE';
        return {
            fieldsUsed,
            joinsUsed,
            filtersApplied,
            aggregationsApplied,
            hasLimit,
            limit,
            hasOrderBy,
            queryType,
        };
    }
    analyzeApiRequest(query) {
        return {
            fieldsUsed: this.extractFieldsFromApiRequest(query),
            joinsUsed: [],
            filtersApplied: this.extractFiltersFromApiRequest(query),
            aggregationsApplied: [],
            hasLimit: false,
            hasOrderBy: false,
            queryType: 'API',
        };
    }
    extractFields(sql) {
        const fields = [];
        const selectMatch = sql.match(/SELECT\s+(.*?)\s+FROM/i);
        if (selectMatch) {
            const selectClause = selectMatch[1];
            const fieldList = selectClause.split(',').map(f => f.trim());
            for (const field of fieldList) {
                const cleanField = field
                    .replace(/\s+AS\s+\w+/i, '')
                    .replace(/^\w+\(/, '')
                    .replace(/\)$/, '')
                    .trim();
                if (cleanField && cleanField !== '*') {
                    fields.push(cleanField);
                }
            }
        }
        return fields;
    }
    extractJoins(sql) {
        const joins = [];
        const joinMatches = sql.matchAll(/(?:INNER|LEFT|RIGHT|FULL)?\s+JOIN\s+(\w+)/gi);
        for (const match of joinMatches) {
            joins.push(match[1]);
        }
        return joins;
    }
    extractFilters(sql) {
        const filters = [];
        const whereMatch = sql.match(/WHERE\s+(.*?)(?:\s+(?:GROUP|ORDER|LIMIT)|$)/i);
        if (whereMatch) {
            const whereClause = whereMatch[1];
            const conditions = whereClause.split(/\s+(?:AND|OR)\s+/i);
            for (const condition of conditions) {
                const filter = this.parseCondition(condition);
                if (filter) {
                    filters.push(filter);
                }
            }
        }
        return filters;
    }
    parseCondition(condition) {
        const patterns = [
            { regex: /(\w+)\s*=\s*['"]?([^'"]+)['"]?/i, operator: '=' },
            { regex: /(\w+)\s*!=\s*['"]?([^'"]+)['"]?/i, operator: '!=' },
            { regex: /(\w+)\s*>\s*(\d+)/i, operator: '>' },
            { regex: /(\w+)\s*<\s*(\d+)/i, operator: '<' },
            { regex: /(\w+)\s*>=\s*(\d+)/i, operator: '>=' },
            { regex: /(\w+)\s*<=\s*(\d+)/i, operator: '<=' },
            { regex: /(\w+)\s+IN\s*\(([^)]+)\)/i, operator: 'IN' },
        ];
        for (const pattern of patterns) {
            const match = condition.match(pattern.regex);
            if (match) {
                let value = match[2];
                if (pattern.operator === 'IN') {
                    value = match[2].split(',').map(v => v.trim().replace(/['"]/g, ''));
                }
                else if (!isNaN(Number(value))) {
                    value = Number(value);
                }
                else {
                    value = value.replace(/['"]/g, '');
                }
                return {
                    field: match[1],
                    operator: pattern.operator,
                    value,
                };
            }
        }
        return null;
    }
    extractAggregations(sql) {
        const aggregations = [];
        const aggFunctions = ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'GROUP_CONCAT'];
        for (const func of aggFunctions) {
            const regex = new RegExp(`\\b${func}\\s*\\(`, 'gi');
            if (regex.test(sql)) {
                aggregations.push(func);
            }
        }
        return aggregations;
    }
    extractFieldsFromApiRequest(query) {
        return [];
    }
    extractFiltersFromApiRequest(query) {
        const filters = [];
        if (query.requestBody) {
            for (const [key, value] of Object.entries(query.requestBody)) {
                if (typeof value === 'string' || typeof value === 'number') {
                    filters.push({
                        field: key,
                        operator: '=',
                        value,
                    });
                }
            }
        }
        return filters;
    }
}
exports.QueryAnalyzer = QueryAnalyzer;
//# sourceMappingURL=query-analyzer.js.map