"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyDecisionPoint = void 0;
class PolicyDecisionPoint {
    constructor(config) {
        this.config = config;
        this.policyCache = new Map();
    }
    async evaluate(request) {
        if (this.config.cacheDecisions) {
            const cacheKey = this.generateCacheKey(request);
            const cached = this.policyCache.get(cacheKey);
            if (cached) {
                return cached;
            }
        }
        const mode = this.config.policyMode || 'hybrid';
        let decision;
        switch (this.config.policyEngine) {
            case 'opa':
                decision = await this.evaluateWithOPA(request);
                break;
            case 'cedar':
                decision = await this.evaluateWithCedar(request);
                break;
            default:
                if (mode === 'abac' || (mode === 'hybrid' && this.config.abacPolicies && this.config.abacPolicies.length > 0)) {
                    decision = await this.evaluateWithABAC(request);
                }
                else if (mode === 'rbac') {
                    decision = await this.evaluateWithRBAC(request);
                }
                else {
                    decision = await this.evaluateWithABAC(request);
                    if (!decision.allowed) {
                        const rbacDecision = await this.evaluateWithRBAC(request);
                        if (rbacDecision.allowed) {
                            decision = {
                                ...rbacDecision,
                                appliedRules: [...decision.appliedRules, ...rbacDecision.appliedRules],
                            };
                        }
                    }
                }
        }
        if (this.config.cacheDecisions) {
            const cacheKey = this.generateCacheKey(request);
            this.policyCache.set(cacheKey, decision);
        }
        return decision;
    }
    async evaluateWithABAC(request) {
        const policies = this.config.abacPolicies || [];
        const appliedRules = [];
        const sortedPolicies = [...policies].sort((a, b) => (b.priority || 0) - (a.priority || 0));
        for (const policy of sortedPolicies) {
            const matches = this.evaluateABACPolicy(policy, request);
            if (matches) {
                appliedRules.push(policy.id);
                return {
                    allowed: policy.effect === 'allow',
                    reason: `ABAC policy "${policy.name}" ${policy.effect === 'allow' ? 'allows' : 'denies'} access`,
                    appliedRules,
                    conditions: {
                        policyId: policy.id,
                        policyName: policy.name,
                        matchedConditions: policy.conditions,
                    },
                };
            }
        }
        return {
            allowed: false,
            reason: 'No ABAC policy matched - default deny',
            appliedRules,
        };
    }
    evaluateABACPolicy(policy, request) {
        let allConditionsMatch = true;
        let anyConditionMatches = false;
        for (let i = 0; i < policy.conditions.length; i++) {
            const condition = policy.conditions[i];
            const matches = this.evaluateABACCondition(condition, request);
            if (i > 0 && condition.logicalOperator === 'OR') {
                anyConditionMatches = anyConditionMatches || matches;
                if (anyConditionMatches) {
                    return true;
                }
            }
            else {
                allConditionsMatch = allConditionsMatch && matches;
                if (!allConditionsMatch) {
                    return false;
                }
            }
        }
        return allConditionsMatch;
    }
    evaluateABACCondition(condition, request) {
        const { attribute, operator, value } = condition;
        const actualValue = this.resolveAttribute(attribute, request);
        if (actualValue === undefined) {
            return false;
        }
        switch (operator) {
            case 'equals':
                return actualValue === value;
            case 'notEquals':
                return actualValue !== value;
            case 'in':
                return Array.isArray(value) && value.includes(actualValue);
            case 'notIn':
                return Array.isArray(value) && !value.includes(actualValue);
            case 'greaterThan':
                return Number(actualValue) > Number(value);
            case 'lessThan':
                return Number(actualValue) < Number(value);
            case 'contains':
                return String(actualValue).includes(String(value));
            case 'startsWith':
                return String(actualValue).startsWith(String(value));
            case 'endsWith':
                return String(actualValue).endsWith(String(value));
            case 'regex':
                return new RegExp(value).test(String(actualValue));
            default:
                return false;
        }
    }
    resolveAttribute(attribute, request) {
        const parts = attribute.split('.');
        if (parts.length < 2) {
            return undefined;
        }
        const [entity, ...path] = parts;
        let source;
        switch (entity) {
            case 'subject':
                source = request.subject.attributes;
                break;
            case 'resource':
                source = request.resource.attributes;
                break;
            case 'context':
                source = { ...request.context, ...(request.context.additionalAttributes || {}) };
                break;
            default:
                return undefined;
        }
        let value = source;
        for (const key of path) {
            if (value && typeof value === 'object') {
                if (key in value) {
                    value = value[key];
                }
                else {
                    let found = false;
                    for (const nestedKey in value) {
                        if (value[nestedKey] && typeof value[nestedKey] === 'object' && key in value[nestedKey]) {
                            value = value[nestedKey][key];
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return undefined;
                    }
                }
            }
            else {
                return undefined;
            }
        }
        return value;
    }
    async evaluateWithRBAC(request) {
        const role = request.subject.attributes.role;
        const resourceType = request.resource.type;
        const sensitivity = request.resource.attributes.sensitivity || 'internal';
        const appliedRules = [];
        let allowed = false;
        let reason = '';
        if (role === 'admin') {
            allowed = true;
            reason = 'Admin has full access';
            appliedRules.push('admin-full-access');
        }
        else if (role === 'researcher' || role === 'analyst') {
            if (sensitivity === 'public' || sensitivity === 'internal') {
                allowed = true;
                reason = `${role} can access public/internal resources`;
                appliedRules.push(`${role}-public-internal-access`);
            }
            else if (sensitivity === 'confidential') {
                if (request.context.ipAddress) {
                    allowed = true;
                    reason = `${role} can access confidential resources with IP validation`;
                    appliedRules.push(`${role}-confidential-with-context`);
                }
                else {
                    allowed = false;
                    reason = `${role} requires IP validation for confidential resources`;
                    appliedRules.push(`${role}-confidential-context-required`);
                }
            }
            else {
                allowed = false;
                reason = `${role} cannot access restricted resources`;
                appliedRules.push(`${role}-restricted-denied`);
            }
        }
        else if (role === 'viewer') {
            if (sensitivity === 'public') {
                allowed = true;
                reason = 'Viewer can access public resources';
                appliedRules.push('viewer-public-access');
            }
            else {
                allowed = false;
                reason = 'Viewer can only access public resources';
                appliedRules.push('viewer-restricted');
            }
        }
        else {
            allowed = false;
            reason = `Unknown role: ${role}`;
            appliedRules.push('unknown-role-denied');
        }
        if (allowed && sensitivity === 'restricted') {
            const timeOfDay = request.context.timeOfDay;
            if (timeOfDay) {
                const hour = parseInt(timeOfDay.split(':')[0]);
                if (hour < 8 || hour > 18) {
                    allowed = false;
                    reason = 'Restricted resources only accessible during business hours (8-18)';
                    appliedRules.push('time-restriction-violated');
                }
                else {
                    appliedRules.push('time-restriction-passed');
                }
            }
        }
        return {
            allowed,
            reason,
            appliedRules,
            conditions: {
                role,
                resourceType,
                sensitivity,
                context: request.context,
                policyMode: 'rbac',
            },
        };
    }
    async evaluateWithOPA(request) {
        try {
            const opaEndpoint = this.config.pdpEndpoint || process.env.OPA_ENDPOINT || 'http://localhost:8181';
            const policyPath = process.env.OPA_POLICY_PATH || '/v1/data/authz/allow';
            const input = {
                subject: {
                    id: request.subject.id,
                    attributes: request.subject.attributes,
                },
                resource: {
                    id: request.resource.id,
                    type: request.resource.type,
                    attributes: request.resource.attributes,
                },
                context: request.context,
                action: request.action || 'read',
            };
            const response = await fetch(`${opaEndpoint}${policyPath}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ input }),
            });
            if (!response.ok) {
                throw new Error(`OPA request failed: ${response.statusText}`);
            }
            const result = await response.json();
            const allowed = result.result === true;
            return {
                allowed,
                reason: allowed
                    ? 'OPA policy evaluation: allowed'
                    : 'OPA policy evaluation: denied',
                appliedRules: ['opa-policy'],
                conditions: {
                    opaResult: result,
                    policyMode: 'opa',
                },
            };
        }
        catch (error) {
            console.warn(`OPA evaluation failed: ${error.message}, falling back to RBAC`);
            return this.evaluateWithRBAC(request);
        }
    }
    async evaluateWithCedar(request) {
        try {
            let Cedar;
            try {
                Cedar = require('@cedar-policy/cedar');
            }
            catch (e) {
                return await this.evaluateWithCedarAPI(request);
            }
            const authorizer = new Cedar.Authorizer();
            const principal = Cedar.Entity.fromJSON({
                type: 'User',
                id: request.subject.id,
                attrs: request.subject.attributes,
            });
            const resource = Cedar.Entity.fromJSON({
                type: request.resource.type,
                id: request.resource.id,
                attrs: request.resource.attributes,
            });
            const action = Cedar.Action.fromString(request.action || 'read');
            const context = Cedar.Context.fromJSON(request.context);
            const policySet = Cedar.PolicySet.fromPolicies([]);
            const decision = authorizer.isAuthorized(principal, action, resource, context, policySet);
            return {
                allowed: decision === Cedar.Decision.Allow,
                reason: decision === Cedar.Decision.Allow
                    ? 'Cedar policy evaluation: allowed'
                    : 'Cedar policy evaluation: denied',
                appliedRules: ['cedar-policy'],
                conditions: {
                    decision,
                    policyMode: 'cedar',
                },
            };
        }
        catch (error) {
            console.warn(`Cedar evaluation failed: ${error.message}, falling back to RBAC`);
            return this.evaluateWithRBAC(request);
        }
    }
    async evaluateWithCedarAPI(request) {
        try {
            const cedarEndpoint = this.config.pdpEndpoint || process.env.CEDAR_ENDPOINT || 'http://localhost:3000';
            const response = await fetch(`${cedarEndpoint}/authorize`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    principal: {
                        type: 'User',
                        id: request.subject.id,
                        attributes: request.subject.attributes,
                    },
                    action: request.action || 'read',
                    resource: {
                        type: request.resource.type,
                        id: request.resource.id,
                        attributes: request.resource.attributes,
                    },
                    context: request.context,
                }),
            });
            if (!response.ok) {
                throw new Error(`Cedar API request failed: ${response.statusText}`);
            }
            const result = await response.json();
            const allowed = result.decision === 'Allow';
            return {
                allowed,
                reason: allowed
                    ? 'Cedar API evaluation: allowed'
                    : 'Cedar API evaluation: denied',
                appliedRules: ['cedar-policy'],
                conditions: {
                    cedarResult: result,
                    policyMode: 'cedar',
                },
            };
        }
        catch (error) {
            console.warn(`Cedar API evaluation failed: ${error.message}, falling back to RBAC`);
            return this.evaluateWithRBAC(request);
        }
    }
    generateCacheKey(request) {
        return JSON.stringify({
            subjectId: request.subject.id,
            role: request.subject.attributes.role,
            resourceId: request.resource.id,
            resourceType: request.resource.type,
            context: request.context,
        });
    }
    clearCache() {
        this.policyCache.clear();
    }
}
exports.PolicyDecisionPoint = PolicyDecisionPoint;
//# sourceMappingURL=policy-decision-point.js.map