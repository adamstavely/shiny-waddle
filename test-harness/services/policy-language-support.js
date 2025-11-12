"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyLanguageSupport = void 0;
class PolicyLanguageSupport {
    constructor() {
        this.adapters = new Map();
        this.registerAdapter(new XACMLAdapter());
        this.registerAdapter(new RegoAdapter());
        this.registerAdapter(new CedarAdapter());
    }
    registerAdapter(adapter) {
        this.adapters.set(adapter.name.toLowerCase(), adapter);
    }
    getAdapter(language) {
        return this.adapters.get(language.toLowerCase()) || null;
    }
    async evaluate(language, request, policy) {
        const adapter = this.getAdapter(language);
        if (!adapter) {
            throw new Error(`Unsupported policy language: ${language}`);
        }
        return adapter.evaluate(request, policy);
    }
    convertPolicy(fromLanguage, toLanguage, policy) {
        const fromAdapter = this.getAdapter(fromLanguage);
        const toAdapter = this.getAdapter(toLanguage);
        if (!fromAdapter || !toAdapter) {
            throw new Error('Unsupported policy language');
        }
        const abacPolicy = fromAdapter.convertToABAC(policy);
        return toAdapter.convertFromABAC(abacPolicy);
    }
    validate(language, policy) {
        const adapter = this.getAdapter(language);
        if (!adapter) {
            return { valid: false, errors: [`Unsupported policy language: ${language}`] };
        }
        return adapter.validate(policy);
    }
}
exports.PolicyLanguageSupport = PolicyLanguageSupport;
class XACMLAdapter {
    constructor() {
        this.name = 'xacml';
    }
    async evaluate(request, policy) {
        try {
            let xacml;
            try {
                xacml = require('xacml-js');
            }
            catch (e) {
                return this.evaluateXACMLBasic(request, policy);
            }
            const xacmlPolicy = policy.Policy || policy;
            const pdp = new xacml.PDP();
            const xacmlRequest = this.createXACMLRequest(request);
            const response = pdp.evaluate(xacmlRequest, xacmlPolicy);
            const decision = response.Decision;
            const allowed = decision === 'Permit';
            return {
                allowed,
                reason: `XACML policy evaluation: ${decision}`,
                appliedRules: [xacmlPolicy.PolicyId || 'xacml-policy'],
                conditions: {
                    xacmlResponse: response,
                    policyMode: 'xacml',
                },
            };
        }
        catch (error) {
            return this.evaluateXACMLBasic(request, policy);
        }
    }
    evaluateXACMLBasic(request, policy) {
        const xacmlPolicy = policy.Policy || policy;
        const rules = xacmlPolicy.Rule || (xacmlPolicy.Rules ? xacmlPolicy.Rules.Rule : []);
        const ruleArray = Array.isArray(rules) ? rules : [rules];
        for (const rule of ruleArray) {
            if (this.evaluateXACMLTarget(rule.Target, request)) {
                const effect = rule.Effect || 'Deny';
                return {
                    allowed: effect === 'Permit',
                    reason: `XACML rule ${rule.RuleId || 'unknown'}: ${effect}`,
                    appliedRules: [rule.RuleId || 'xacml-rule'],
                    conditions: {
                        ruleEffect: effect,
                        policyMode: 'xacml',
                    },
                };
            }
        }
        return {
            allowed: false,
            reason: 'XACML policy: No matching rule found (default deny)',
            appliedRules: [],
        };
    }
    evaluateXACMLTarget(target, request) {
        if (!target)
            return true;
        const anyOf = target.AnyOf || [];
        for (const anyOfItem of anyOf) {
            const allOf = anyOfItem.AllOf || [];
            let allMatch = true;
            for (const allOfItem of allOf) {
                const matches = allOfItem.Match || [];
                for (const match of matches) {
                    if (!this.evaluateXACMLMatch(match, request)) {
                        allMatch = false;
                        break;
                    }
                }
            }
            if (allMatch)
                return true;
        }
        return false;
    }
    evaluateXACMLMatch(match, request) {
        const attributeValue = match.AttributeValue?.Value || match.AttributeValue;
        const attributeId = match.AttributeDesignator?.AttributeId || match.AttributeId;
        const matchId = match.MatchId || 'urn:oasis:names:tc:xacml:1.0:function:string-equal';
        const requestValue = this.resolveXACMLAttribute(attributeId, request);
        switch (matchId) {
            case 'urn:oasis:names:tc:xacml:1.0:function:string-equal':
                return String(requestValue) === String(attributeValue);
            case 'urn:oasis:names:tc:xacml:1.0:function:string-regexp-match':
                return new RegExp(attributeValue).test(String(requestValue));
            default:
                return String(requestValue) === String(attributeValue);
        }
    }
    resolveXACMLAttribute(attributeId, request) {
        const attributeMap = {
            'urn:oasis:names:tc:xacml:1.0:subject:subject-id': 'subject.id',
            'urn:oasis:names:tc:xacml:1.0:subject:role': 'subject.attributes.role',
            'urn:oasis:names:tc:xacml:1.0:resource:resource-id': 'resource.id',
            'urn:oasis:names:tc:xacml:1.0:resource:resource-type': 'resource.type',
        };
        const path = attributeMap[attributeId] || attributeId;
        const parts = path.split('.');
        let value = request;
        for (const part of parts) {
            if (value && typeof value === 'object') {
                value = value[part];
            }
            else {
                return undefined;
            }
        }
        return value;
    }
    createXACMLRequest(request) {
        return {
            Request: {
                AccessSubject: {
                    Attribute: [
                        {
                            AttributeId: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
                            Value: request.subject.id,
                        },
                        {
                            AttributeId: 'urn:oasis:names:tc:xacml:1.0:subject:role',
                            Value: request.subject.attributes.role,
                        },
                    ],
                },
                Resource: {
                    Attribute: [
                        {
                            AttributeId: 'urn:oasis:names:tc:xacml:1.0:resource:resource-id',
                            Value: request.resource.id,
                        },
                        {
                            AttributeId: 'urn:oasis:names:tc:xacml:1.0:resource:resource-type',
                            Value: request.resource.type,
                        },
                    ],
                },
                Action: {
                    Attribute: [
                        {
                            AttributeId: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
                            Value: request.action || 'read',
                        },
                    ],
                },
            },
        };
    }
    convertFromABAC(abacPolicy) {
        return {
            Policy: {
                PolicyId: abacPolicy.id,
                RuleCombiningAlgId: 'urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable',
                Target: {
                    AnyOf: {
                        AllOf: {
                            Match: this.convertConditionsToXACML(abacPolicy.conditions),
                        },
                    },
                },
                Rule: {
                    RuleId: abacPolicy.id,
                    Effect: abacPolicy.effect === 'allow' ? 'Permit' : 'Deny',
                },
            },
        };
    }
    convertToABAC(policy) {
        const xacmlPolicy = policy.Policy || policy;
        return {
            id: xacmlPolicy.PolicyId || 'xacml-policy',
            name: xacmlPolicy.PolicyId || 'XACML Policy',
            description: '',
            effect: xacmlPolicy.Rule?.Effect === 'Permit' ? 'allow' : 'deny',
            conditions: this.convertXACMLToConditions(xacmlPolicy.Target),
            priority: 0,
        };
    }
    validate(policy) {
        const errors = [];
        if (!policy.Policy && !policy.PolicyId) {
            errors.push('Invalid XACML policy structure');
        }
        return {
            valid: errors.length === 0,
            errors,
        };
    }
    convertConditionsToXACML(conditions) {
        return conditions.map(condition => ({
            AttributeValue: condition.value,
            AttributeDesignator: {
                AttributeId: condition.attribute,
            },
        }));
    }
    convertXACMLToConditions(target) {
        return [];
    }
}
class RegoAdapter {
    constructor() {
        this.name = 'rego';
    }
    async evaluate(request, policy) {
        try {
            const opaEndpoint = process.env.OPA_ENDPOINT || 'http://localhost:8181';
            const policyPath = process.env.OPA_POLICY_PATH || '/v1/data/authz/allow';
            if (typeof policy === 'string') {
                await this.loadRegoPolicyIntoOPA(opaEndpoint, policy);
            }
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
                    ? 'Rego policy evaluation via OPA: allowed'
                    : 'Rego policy evaluation via OPA: denied',
                appliedRules: ['rego-policy'],
                conditions: {
                    opaResult: result,
                    policyMode: 'rego',
                },
            };
        }
        catch (error) {
            return this.evaluateRegoBasic(request, policy);
        }
    }
    async loadRegoPolicyIntoOPA(opaEndpoint, policy) {
        try {
            const policyName = 'test-policy';
            const policyPath = `/v1/policies/${policyName}`;
            const checkResponse = await fetch(`${opaEndpoint}${policyPath}`);
            if (checkResponse.ok) {
                await fetch(`${opaEndpoint}${policyPath}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'text/plain',
                    },
                    body: policy,
                });
            }
            else {
                await fetch(`${opaEndpoint}${policyPath}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'text/plain',
                    },
                    body: policy,
                });
            }
        }
        catch {
        }
    }
    evaluateRegoBasic(request, policy) {
        if (typeof policy === 'string' && policy.includes('allow = true')) {
            const hasAllow = policy.includes('allow = true');
            const hasDeny = policy.includes('allow = false');
            if (hasDeny) {
                return {
                    allowed: false,
                    reason: 'Rego policy: deny rule matched',
                    appliedRules: ['rego-policy'],
                };
            }
            if (hasAllow) {
                return {
                    allowed: true,
                    reason: 'Rego policy: allow rule matched',
                    appliedRules: ['rego-policy'],
                };
            }
        }
        return {
            allowed: false,
            reason: 'Rego policy: No matching rule (default deny)',
            appliedRules: [],
        };
    }
    convertFromABAC(abacPolicy) {
        const conditions = abacPolicy.conditions.map(condition => {
            const attribute = condition.attribute.replace(/\./g, '_');
            const operator = this.convertOperatorToRego(condition.operator);
            const value = this.formatRegoValue(condition.value);
            return `${attribute} ${operator} ${value}`;
        }).join(' and ');
        return `
package policy

default allow = false

allow {
  ${conditions}
}
    `.trim();
    }
    convertToABAC(policy) {
        return {
            id: 'rego-policy',
            name: 'Rego Policy',
            description: '',
            effect: policy.includes('allow = true') ? 'allow' : 'deny',
            conditions: [],
            priority: 0,
        };
    }
    validate(policy) {
        const errors = [];
        if (typeof policy === 'string') {
            if (!policy.includes('package')) {
                errors.push('Rego policy must start with package declaration');
            }
            const openBraces = (policy.match(/\{/g) || []).length;
            const closeBraces = (policy.match(/\}/g) || []).length;
            if (openBraces !== closeBraces) {
                errors.push('Unbalanced braces in Rego policy');
            }
            const openParens = (policy.match(/\(/g) || []).length;
            const closeParens = (policy.match(/\)/g) || []).length;
            if (openParens !== closeParens) {
                errors.push('Unbalanced parentheses in Rego policy');
            }
            this.validateRegoWithOPA(policy).then(opaErrors => {
                errors.push(...opaErrors);
            }).catch(() => {
            });
        }
        else {
            errors.push('Rego policy must be a string');
        }
        return {
            valid: errors.length === 0,
            errors,
        };
    }
    async validateRegoWithOPA(policy) {
        const errors = [];
        try {
            const opaEndpoint = process.env.OPA_ENDPOINT || 'http://localhost:8181';
            const response = await fetch(`${opaEndpoint}/v1/compile`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: 'data.authz.allow',
                    input: {},
                    unknown: [],
                }),
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                errors.push(`OPA compilation failed: ${errorData.message || response.statusText}`);
            }
        }
        catch {
        }
        return errors;
    }
    convertOperatorToRego(operator) {
        const mapping = {
            'equals': '==',
            'notEquals': '!=',
            'in': 'in',
            'notIn': 'not in',
            'greaterThan': '>',
            'lessThan': '<',
        };
        return mapping[operator] || '==';
    }
    formatRegoValue(value) {
        if (typeof value === 'string') {
            return `"${value}"`;
        }
        if (Array.isArray(value)) {
            return `[${value.map(v => this.formatRegoValue(v)).join(', ')}]`;
        }
        return String(value);
    }
}
class CedarAdapter {
    constructor() {
        this.name = 'cedar';
    }
    async evaluate(request, policy) {
        try {
            let Cedar;
            try {
                Cedar = require('@cedar-policy/cedar');
            }
            catch (e) {
                return await this.evaluateCedarViaAPI(request, policy);
            }
            const policySet = typeof policy === 'string'
                ? Cedar.PolicySet.fromPolicies([Cedar.Policy.fromString(policy)])
                : Cedar.PolicySet.fromJSON(policy);
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
            const authorizer = new Cedar.Authorizer();
            const response = authorizer.isAuthorized(principal, action, resource, context, policySet);
            const allowed = response === Cedar.Decision.Allow;
            return {
                allowed,
                reason: allowed
                    ? 'Cedar policy evaluation: allowed'
                    : 'Cedar policy evaluation: denied',
                appliedRules: ['cedar-policy'],
                conditions: {
                    decision: response,
                    policyMode: 'cedar',
                },
            };
        }
        catch (error) {
            return await this.evaluateCedarViaAPI(request, policy);
        }
    }
    async evaluateCedarViaAPI(request, policy) {
        try {
            const cedarEndpoint = process.env.CEDAR_ENDPOINT || 'http://localhost:3000';
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
                    policies: typeof policy === 'string' ? [policy] : policy,
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
            return {
                allowed: false,
                reason: `Cedar evaluation failed: ${error.message}`,
                appliedRules: [],
            };
        }
    }
    convertFromABAC(abacPolicy) {
        const conditions = abacPolicy.conditions.map(condition => {
            const attribute = condition.attribute;
            const operator = this.convertOperatorToCedar(condition.operator);
            const value = this.formatCedarValue(condition.value);
            return `${attribute} ${operator} ${value}`;
        }).join(' && ');
        return `
permit(
  principal,
  action,
  resource
) when {
  ${conditions}
};
    `.trim();
    }
    convertToABAC(policy) {
        return {
            id: 'cedar-policy',
            name: 'Cedar Policy',
            description: '',
            effect: policy.includes('permit') ? 'allow' : 'deny',
            conditions: [],
            priority: 0,
        };
    }
    validate(policy) {
        const errors = [];
        if (typeof policy === 'string' && !policy.includes('permit') && !policy.includes('forbid')) {
            errors.push('Cedar policy must contain permit or forbid');
        }
        return {
            valid: errors.length === 0,
            errors,
        };
    }
    convertOperatorToCedar(operator) {
        const mapping = {
            'equals': '==',
            'notEquals': '!=',
            'in': 'in',
            'greaterThan': '>',
            'lessThan': '<',
        };
        return mapping[operator] || '==';
    }
    formatCedarValue(value) {
        if (typeof value === 'string') {
            return `"${value}"`;
        }
        if (Array.isArray(value)) {
            return `[${value.map(v => this.formatCedarValue(v)).join(', ')}]`;
        }
        return String(value);
    }
}
//# sourceMappingURL=policy-language-support.js.map