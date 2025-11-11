/**
 * Additional Policy Language Support
 * 
 * Support for XACML, Rego (OPA), Cedar, and other policy languages
 */

import { ABACPolicy } from '../core/types';
import { PDPRequest, PDPDecision } from './policy-decision-point';

export interface PolicyLanguageAdapter {
  name: string;
  evaluate(request: PDPRequest, policy: any): Promise<PDPDecision>;
  convertFromABAC(abacPolicy: ABACPolicy): any;
  convertToABAC(policy: any): ABACPolicy;
  validate(policy: any): { valid: boolean; errors: string[] };
}

export class PolicyLanguageSupport {
  private adapters: Map<string, PolicyLanguageAdapter> = new Map();

  constructor() {
    // Register built-in adapters
    this.registerAdapter(new XACMLAdapter());
    this.registerAdapter(new RegoAdapter());
    this.registerAdapter(new CedarAdapter());
  }

  /**
   * Register a policy language adapter
   */
  registerAdapter(adapter: PolicyLanguageAdapter): void {
    this.adapters.set(adapter.name.toLowerCase(), adapter);
  }

  /**
   * Get adapter for language
   */
  getAdapter(language: string): PolicyLanguageAdapter | null {
    return this.adapters.get(language.toLowerCase()) || null;
  }

  /**
   * Evaluate policy in specific language
   */
  async evaluate(
    language: string,
    request: PDPRequest,
    policy: any
  ): Promise<PDPDecision> {
    const adapter = this.getAdapter(language);
    if (!adapter) {
      throw new Error(`Unsupported policy language: ${language}`);
    }

    return adapter.evaluate(request, policy);
  }

  /**
   * Convert ABAC policy to another language
   */
  convertPolicy(
    fromLanguage: string,
    toLanguage: string,
    policy: any
  ): any {
    const fromAdapter = this.getAdapter(fromLanguage);
    const toAdapter = this.getAdapter(toLanguage);

    if (!fromAdapter || !toAdapter) {
      throw new Error('Unsupported policy language');
    }

    // Convert: fromLanguage -> ABAC -> toLanguage
    const abacPolicy = fromAdapter.convertToABAC(policy);
    return toAdapter.convertFromABAC(abacPolicy);
  }

  /**
   * Validate policy in specific language
   */
  validate(language: string, policy: any): { valid: boolean; errors: string[] } {
    const adapter = this.getAdapter(language);
    if (!adapter) {
      return { valid: false, errors: [`Unsupported policy language: ${language}`] };
    }

    return adapter.validate(policy);
  }
}

/**
 * XACML Adapter
 */
class XACMLAdapter implements PolicyLanguageAdapter {
  name = 'xacml';

  async evaluate(request: PDPRequest, policy: any): Promise<PDPDecision> {
    try {
      // Try to use xacml-js library if available
      let xacml: any;
      try {
        xacml = require('xacml-js');
      } catch (e) {
        // Fallback: Implement basic XACML evaluation
        return this.evaluateXACMLBasic(request, policy);
      }

      // Use XACML library for evaluation
      const xacmlPolicy = policy.Policy || policy;
      const pdp = new xacml.PDP();
      
      // Create XACML request
      const xacmlRequest = this.createXACMLRequest(request);
      
      // Evaluate
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
    } catch (error: any) {
      // Fallback to basic evaluation
      return this.evaluateXACMLBasic(request, policy);
    }
  }

  /**
   * Basic XACML evaluation (fallback)
   */
  private evaluateXACMLBasic(request: PDPRequest, policy: any): PDPDecision {
    const xacmlPolicy = policy.Policy || policy;
    const rules = xacmlPolicy.Rule || (xacmlPolicy.Rules ? xacmlPolicy.Rules.Rule : []);
    const ruleArray = Array.isArray(rules) ? rules : [rules];

    // Evaluate each rule
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

    // Default deny if no rule matches
    return {
      allowed: false,
      reason: 'XACML policy: No matching rule found (default deny)',
      appliedRules: [],
    };
  }

  /**
   * Evaluate XACML Target
   */
  private evaluateXACMLTarget(target: any, request: PDPRequest): boolean {
    if (!target) return true; // No target means match all

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

      if (allMatch) return true;
    }

    return false;
  }

  /**
   * Evaluate XACML Match
   */
  private evaluateXACMLMatch(match: any, request: PDPRequest): boolean {
    const attributeValue = match.AttributeValue?.Value || match.AttributeValue;
    const attributeId = match.AttributeDesignator?.AttributeId || match.AttributeId;
    const matchId = match.MatchId || 'urn:oasis:names:tc:xacml:1.0:function:string-equal';

    // Resolve attribute value from request
    const requestValue = this.resolveXACMLAttribute(attributeId, request);

    // Compare based on MatchId
    switch (matchId) {
      case 'urn:oasis:names:tc:xacml:1.0:function:string-equal':
        return String(requestValue) === String(attributeValue);
      case 'urn:oasis:names:tc:xacml:1.0:function:string-regexp-match':
        return new RegExp(attributeValue).test(String(requestValue));
      default:
        return String(requestValue) === String(attributeValue);
    }
  }

  /**
   * Resolve XACML attribute from request
   */
  private resolveXACMLAttribute(attributeId: string, request: PDPRequest): any {
    // Map XACML attribute IDs to request attributes
    const attributeMap: Record<string, string> = {
      'urn:oasis:names:tc:xacml:1.0:subject:subject-id': 'subject.id',
      'urn:oasis:names:tc:xacml:1.0:subject:role': 'subject.attributes.role',
      'urn:oasis:names:tc:xacml:1.0:resource:resource-id': 'resource.id',
      'urn:oasis:names:tc:xacml:1.0:resource:resource-type': 'resource.type',
    };

    const path = attributeMap[attributeId] || attributeId;
    const parts = path.split('.');

    let value: any = request;
    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Create XACML request from PDP request
   */
  private createXACMLRequest(request: PDPRequest): any {
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

  convertFromABAC(abacPolicy: ABACPolicy): any {
    // Convert ABAC policy to XACML
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

  convertToABAC(policy: any): ABACPolicy {
    // Convert XACML to ABAC
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

  validate(policy: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (!policy.Policy && !policy.PolicyId) {
      errors.push('Invalid XACML policy structure');
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private convertConditionsToXACML(conditions: any[]): any[] {
    // Simplified conversion
    return conditions.map(condition => ({
      AttributeValue: condition.value,
      AttributeDesignator: {
        AttributeId: condition.attribute,
      },
    }));
  }

  private convertXACMLToConditions(target: any): any[] {
    // Simplified conversion
    return [];
  }
}

/**
 * Rego (OPA) Adapter
 */
class RegoAdapter implements PolicyLanguageAdapter {
  name = 'rego';

  async evaluate(request: PDPRequest, policy: any): Promise<PDPDecision> {
    try {
      const opaEndpoint = process.env.OPA_ENDPOINT || 'http://localhost:8181';
      const policyPath = process.env.OPA_POLICY_PATH || '/v1/data/authz/allow';

      // If policy is a string (Rego code), we need to load it into OPA first
      if (typeof policy === 'string') {
        // Try to load policy into OPA
        await this.loadRegoPolicyIntoOPA(opaEndpoint, policy);
      }

      // Prepare input for OPA
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

      // Query OPA
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
    } catch (error: any) {
      // Fallback: Basic Rego evaluation (simplified)
      return this.evaluateRegoBasic(request, policy);
    }
  }

  /**
   * Load Rego policy into OPA
   */
  private async loadRegoPolicyIntoOPA(opaEndpoint: string, policy: string): Promise<void> {
    try {
      const policyName = 'test-policy';
      const policyPath = `/v1/policies/${policyName}`;

      // Check if policy already exists
      const checkResponse = await fetch(`${opaEndpoint}${policyPath}`);
      if (checkResponse.ok) {
        // Policy exists, update it
        await fetch(`${opaEndpoint}${policyPath}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'text/plain',
          },
          body: policy,
        });
      } else {
        // Create new policy
        await fetch(`${opaEndpoint}${policyPath}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'text/plain',
          },
          body: policy,
        });
      }
    } catch {
      // Ignore if OPA is not available
    }
  }

  /**
   * Basic Rego evaluation (fallback)
   */
  private evaluateRegoBasic(request: PDPRequest, policy: string): PDPDecision {
    // Very simplified Rego evaluation - just check for "allow = true" pattern
    if (typeof policy === 'string' && policy.includes('allow = true')) {
      // Try to evaluate basic conditions
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

  convertFromABAC(abacPolicy: ABACPolicy): string {
    // Convert ABAC policy to Rego code
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

  convertToABAC(policy: string): ABACPolicy {
    // Parse Rego code and convert to ABAC
    // This is simplified - would need full Rego parser
    
    return {
      id: 'rego-policy',
      name: 'Rego Policy',
      description: '',
      effect: policy.includes('allow = true') ? 'allow' : 'deny',
      conditions: [],
      priority: 0,
    };
  }

  validate(policy: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (typeof policy === 'string') {
      // Basic Rego syntax validation
      if (!policy.includes('package')) {
        errors.push('Rego policy must start with package declaration');
      }

      // Check for balanced braces
      const openBraces = (policy.match(/\{/g) || []).length;
      const closeBraces = (policy.match(/\}/g) || []).length;
      if (openBraces !== closeBraces) {
        errors.push('Unbalanced braces in Rego policy');
      }

      // Check for balanced parentheses
      const openParens = (policy.match(/\(/g) || []).length;
      const closeParens = (policy.match(/\)/g) || []).length;
      if (openParens !== closeParens) {
        errors.push('Unbalanced parentheses in Rego policy');
      }

      // Try to validate with OPA if available
      this.validateRegoWithOPA(policy).then(opaErrors => {
        errors.push(...opaErrors);
      }).catch(() => {
        // OPA not available - skip OPA validation
      });
    } else {
      errors.push('Rego policy must be a string');
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate Rego policy with OPA
   */
  private async validateRegoWithOPA(policy: string): Promise<string[]> {
    const errors: string[] = [];
    
    try {
      const opaEndpoint = process.env.OPA_ENDPOINT || 'http://localhost:8181';
      
      // Compile policy with OPA
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
    } catch {
      // OPA not available - skip validation
    }

    return errors;
  }

  private convertOperatorToRego(operator: string): string {
    const mapping: Record<string, string> = {
      'equals': '==',
      'notEquals': '!=',
      'in': 'in',
      'notIn': 'not in',
      'greaterThan': '>',
      'lessThan': '<',
    };
    
    return mapping[operator] || '==';
  }

  private formatRegoValue(value: any): string {
    if (typeof value === 'string') {
      return `"${value}"`;
    }
    if (Array.isArray(value)) {
      return `[${value.map(v => this.formatRegoValue(v)).join(', ')}]`;
    }
    return String(value);
  }
}

/**
 * Cedar Adapter
 */
class CedarAdapter implements PolicyLanguageAdapter {
  name = 'cedar';

  async evaluate(request: PDPRequest, policy: any): Promise<PDPDecision> {
    try {
      // Try to use Cedar SDK if available
      let Cedar: any;
      try {
        Cedar = require('@cedar-policy/cedar');
      } catch (e) {
        // Fallback: Use Cedar HTTP API
        return await this.evaluateCedarViaAPI(request, policy);
      }

      // Parse Cedar policy
      const policySet = typeof policy === 'string' 
        ? Cedar.PolicySet.fromPolicies([Cedar.Policy.fromString(policy)])
        : Cedar.PolicySet.fromJSON(policy);

      // Create entities
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

      // Create context
      const context = Cedar.Context.fromJSON(request.context);

      // Create authorizer
      const authorizer = new Cedar.Authorizer();
      
      // Authorize
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
    } catch (error: any) {
      // Fallback to API-based evaluation
      return await this.evaluateCedarViaAPI(request, policy);
    }
  }

  /**
   * Evaluate Cedar via HTTP API
   */
  private async evaluateCedarViaAPI(
    request: PDPRequest,
    policy: any
  ): Promise<PDPDecision> {
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
    } catch (error: any) {
      // Final fallback: Basic evaluation
      return {
        allowed: false,
        reason: `Cedar evaluation failed: ${error.message}`,
        appliedRules: [],
      };
    }
  }

  convertFromABAC(abacPolicy: ABACPolicy): string {
    // Convert ABAC policy to Cedar
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

  convertToABAC(policy: string): ABACPolicy {
    // Parse Cedar and convert to ABAC
    return {
      id: 'cedar-policy',
      name: 'Cedar Policy',
      description: '',
      effect: policy.includes('permit') ? 'allow' : 'deny',
      conditions: [],
      priority: 0,
    };
  }

  validate(policy: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (typeof policy === 'string' && !policy.includes('permit') && !policy.includes('forbid')) {
      errors.push('Cedar policy must contain permit or forbid');
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private convertOperatorToCedar(operator: string): string {
    const mapping: Record<string, string> = {
      'equals': '==',
      'notEquals': '!=',
      'in': 'in',
      'greaterThan': '>',
      'lessThan': '<',
    };
    
    return mapping[operator] || '==';
  }

  private formatCedarValue(value: any): string {
    if (typeof value === 'string') {
      return `"${value}"`;
    }
    if (Array.isArray(value)) {
      return `[${value.map(v => this.formatCedarValue(v)).join(', ')}]`;
    }
    return String(value);
  }
}

