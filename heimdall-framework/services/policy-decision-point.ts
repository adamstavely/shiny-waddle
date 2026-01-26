/**
 * Policy Decision Point (PDP) Service
 * 
 * Evaluates access control policies based on subject, resource, and context
 */

import { AccessControlConfig, ABACPolicy, ABACCondition } from '../core/types';

export interface PDPRequest {
  subject: {
    id: string;
    attributes: Record<string, any>;
  };
  resource: {
    id: string;
    type: string;
    attributes: Record<string, any>;
  };
  context: {
    ipAddress?: string;
    timeOfDay?: string;
    location?: string;
    device?: string;
    additionalAttributes?: Record<string, any>;
  };
  action?: string; // e.g., 'read', 'write', 'delete', 'export'
}

export interface PDPDecision {
  allowed: boolean;
  reason: string;
  appliedRules: string[];
  conditions?: Record<string, any>;
}

export class PolicyDecisionPoint {
  private config: AccessControlConfig;
  private policyCache: Map<string, PDPDecision>;

  constructor(config: AccessControlConfig) {
    this.config = config;
    this.policyCache = new Map();
  }

  /**
   * Evaluate an access control decision
   */
  async evaluate(request: PDPRequest): Promise<PDPDecision> {
    // Check cache if enabled
    if (this.config.cacheDecisions) {
      const cacheKey = this.generateCacheKey(request);
      const cached = this.policyCache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }

    // Determine evaluation mode
    const mode = this.config.policyMode || 'hybrid';
    let decision: PDPDecision;

    // Evaluate based on policy engine
    switch (this.config.policyEngine) {
      case 'opa':
        decision = await this.evaluateWithOPA(request);
        break;
      case 'cedar':
        decision = await this.evaluateWithCedar(request);
        break;
      default:
        // Evaluate based on mode
        if (mode === 'abac' || (mode === 'hybrid' && this.config.abacPolicies && this.config.abacPolicies.length > 0)) {
          decision = await this.evaluateWithABAC(request);
        } else if (mode === 'rbac') {
          decision = await this.evaluateWithRBAC(request);
        } else {
          // Hybrid: Try ABAC first, fall back to RBAC
          decision = await this.evaluateWithABAC(request);
          if (!decision.allowed) {
            const rbacDecision = await this.evaluateWithRBAC(request);
            // If RBAC allows, use that; otherwise keep ABAC denial
            if (rbacDecision.allowed) {
              decision = {
                ...rbacDecision,
                appliedRules: [...decision.appliedRules, ...rbacDecision.appliedRules],
              };
            }
          }
        }
    }

    // Cache decision if enabled
    if (this.config.cacheDecisions) {
      const cacheKey = this.generateCacheKey(request);
      this.policyCache.set(cacheKey, decision);
    }

    return decision;
  }

  /**
   * Evaluate with ABAC (Attribute-Based Access Control)
   */
  private async evaluateWithABAC(request: PDPRequest): Promise<PDPDecision> {
    const policies = this.config.abacPolicies || [];
    const appliedRules: string[] = [];

    // Sort policies by priority (higher priority first)
    const sortedPolicies = [...policies].sort((a, b) => (b.priority || 0) - (a.priority || 0));

    // Evaluate each policy
    for (const policy of sortedPolicies) {
      const matches = this.evaluateABACPolicy(policy, request);
      
      if (matches) {
        appliedRules.push(policy.id);
        
        // First matching policy determines the decision
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

    // No policy matched - default deny
    return {
      allowed: false,
      reason: 'No ABAC policy matched - default deny',
      appliedRules,
    };
  }

  /**
   * Evaluate if an ABAC policy matches the request
   */
  private evaluateABACPolicy(policy: ABACPolicy, request: PDPRequest): boolean {
    // All conditions must match (AND logic by default)
    let allConditionsMatch = true;
    let anyConditionMatches = false; // For OR logic

    for (let i = 0; i < policy.conditions.length; i++) {
      const condition = policy.conditions[i];
      const matches = this.evaluateABACCondition(condition, request);

      // Check logical operator
      if (i > 0 && condition.logicalOperator === 'OR') {
        anyConditionMatches = anyConditionMatches || matches;
        // If OR, we need at least one match
        if (anyConditionMatches) {
          return true;
        }
      } else {
        // AND logic (default)
        allConditionsMatch = allConditionsMatch && matches;
        if (!allConditionsMatch) {
          return false;
        }
      }
    }

    return allConditionsMatch;
  }

  /**
   * Evaluate a single ABAC condition
   */
  private evaluateABACCondition(condition: ABACCondition, request: PDPRequest): boolean {
    const { attribute, operator, value } = condition;

    // Resolve attribute value from request
    const actualValue = this.resolveAttribute(attribute, request);

    if (actualValue === undefined) {
      return false; // Attribute not found
    }

    // Evaluate based on operator
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

  /**
   * Resolve attribute value from request using dot notation
   * Supports: subject.attribute, resource.attribute, context.attribute
   * Also supports nested attributes like subject.abacAttributes.department
   * Extended to support agent-specific attributes: agentType, userContext, serviceAccess
   */
  private resolveAttribute(attribute: string, request: PDPRequest): any {
    const parts = attribute.split('.');
    if (parts.length < 2) {
      return undefined;
    }

    const [entity, ...path] = parts;
    let source: any;

    switch (entity) {
      case 'subject':
        source = request.subject.attributes;
        // Support agent-specific subject attributes
        if (source.agentType) {
          // Add agent-specific attributes to source
          source = {
            ...source,
            agentScopes: source.agentScopes || [],
            userPermissions: source.userPermissions || [],
          };
        }
        break;
      case 'resource':
        source = request.resource.attributes;
        break;
      case 'context':
        source = { ...request.context, ...(request.context.additionalAttributes || {}) };
        // Support agent-specific context attributes
        if (request.context.agentType) {
          source.agentType = request.context.agentType;
        }
        if (request.context.userContext) {
          source.userContext = request.context.userContext;
          source.userPermissions = request.context.userContext.permissions || [];
        }
        if (request.context.serviceAccess) {
          source.serviceAccess = request.context.serviceAccess;
        }
        if (request.context.jitAccess !== undefined) {
          source.jitAccess = request.context.jitAccess;
        }
        if (request.context.auditEnabled !== undefined) {
          source.auditEnabled = request.context.auditEnabled;
        }
        break;
      default:
        return undefined;
    }

    // Navigate nested path
    let value = source;
    for (const key of path) {
      if (value && typeof value === 'object') {
        // Check if key exists directly
        if (key in value) {
          value = value[key];
        } else {
          // Try to find in nested objects (for ABAC attributes)
          let found = false;
          for (const nestedKey in value) {
            if (value[nestedKey] && typeof value[nestedKey] === 'object' && key in value[nestedKey]) {
              value = value[nestedKey][key];
              found = true;
              break;
            }
          }
          if (!found) {
            // Special handling for agent-specific attributes
            // Check if we're looking for userPermissions in context
            if (key === 'userPermissions' && source.userContext) {
              value = source.userContext.permissions || [];
              found = true;
            } else if (key === 'agentType' && source.agentType) {
              value = source.agentType;
              found = true;
            } else if (key === 'serviceAccess' && source.serviceAccess) {
              value = source.serviceAccess;
              found = true;
            }
            if (!found) {
              return undefined;
            }
          }
        }
      } else {
        return undefined;
      }
    }

    // Handle template variables like {{action}} and {{resource.type}}
    if (typeof value === 'string' && value.includes('{{')) {
      const templateMatch = value.match(/\{\{(\w+(?:\.\w+)*)\}\}/);
      if (templateMatch) {
        const templateVar = templateMatch[1];
        const templateValue = this.resolveTemplateVariable(templateVar, request);
        if (templateValue !== undefined) {
          value = value.replace(/\{\{[^}]+\}\}/g, String(templateValue));
        }
      }
    }

    return value;
  }

  /**
   * Resolve template variables like {{action}} or {{resource.type}}
   */
  private resolveTemplateVariable(variable: string, request: PDPRequest): any {
    const parts = variable.split('.');
    if (parts.length === 1) {
      // Simple variable like {{action}}
      if (variable === 'action') {
        return request.action || 'read';
      }
    } else if (parts.length === 2) {
      // Nested variable like {{resource.type}}
      const [entity, attr] = parts;
      if (entity === 'resource' && attr === 'type') {
        return request.resource.type;
      }
      if (entity === 'resource' && attr in request.resource.attributes) {
        return request.resource.attributes[attr];
      }
    }
    return undefined;
  }

  /**
   * Evaluate with RBAC (Role-Based Access Control)
   */
  private async evaluateWithRBAC(request: PDPRequest): Promise<PDPDecision> {
    const role = request.subject.attributes.role;
    const resourceType = request.resource.type;
    const sensitivity = request.resource.attributes.sensitivity || 'internal';

    const appliedRules: string[] = [];
    let allowed = false;
    let reason = '';

    // Role-based access rules
    if (role === 'admin') {
      allowed = true;
      reason = 'Admin has full access';
      appliedRules.push('admin-full-access');
    } else if (role === 'researcher' || role === 'analyst') {
      if (sensitivity === 'public' || sensitivity === 'internal') {
        allowed = true;
        reason = `${role} can access public/internal resources`;
        appliedRules.push(`${role}-public-internal-access`);
      } else if (sensitivity === 'confidential') {
        // Check for additional context requirements
        if (request.context.ipAddress) {
          allowed = true;
          reason = `${role} can access confidential resources with IP validation`;
          appliedRules.push(`${role}-confidential-with-context`);
        } else {
          allowed = false;
          reason = `${role} requires IP validation for confidential resources`;
          appliedRules.push(`${role}-confidential-context-required`);
        }
      } else {
        allowed = false;
        reason = `${role} cannot access restricted resources`;
        appliedRules.push(`${role}-restricted-denied`);
      }
    } else if (role === 'viewer') {
      if (sensitivity === 'public') {
        allowed = true;
        reason = 'Viewer can access public resources';
        appliedRules.push('viewer-public-access');
      } else {
        allowed = false;
        reason = 'Viewer can only access public resources';
        appliedRules.push('viewer-restricted');
      }
    } else {
      allowed = false;
      reason = `Unknown role: ${role}`;
      appliedRules.push('unknown-role-denied');
    }

    // Time-based restrictions
    if (allowed && sensitivity === 'restricted') {
      const timeOfDay = request.context.timeOfDay;
      if (timeOfDay) {
        const hour = parseInt(timeOfDay.split(':')[0]);
        if (hour < 8 || hour > 18) {
          allowed = false;
          reason = 'Restricted resources only accessible during business hours (8-18)';
          appliedRules.push('time-restriction-violated');
        } else {
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

  /**
   * Evaluate with OPA (Open Policy Agent)
   */
  private async evaluateWithOPA(request: PDPRequest): Promise<PDPDecision> {
    try {
      const opaEndpoint = this.config.pdpEndpoint || process.env.OPA_ENDPOINT || 'http://localhost:8181';
      const policyPath = process.env.OPA_POLICY_PATH || '/v1/data/authz/allow';

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

      // Make request to OPA
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
    } catch (error: any) {
      // Fallback to RBAC if OPA is unavailable
      console.warn(`OPA evaluation failed: ${error.message}, falling back to RBAC`);
      return this.evaluateWithRBAC(request);
    }
  }

  /**
   * Evaluate with Cedar
   */
  private async evaluateWithCedar(request: PDPRequest): Promise<PDPDecision> {
    try {
      // Try to use Cedar SDK if available
      let Cedar: any;
      try {
        Cedar = require('@cedar-policy/cedar');
      } catch (e) {
        // Fallback: Use Cedar HTTP API if SDK not available
        return await this.evaluateWithCedarAPI(request);
      }

      // Create Cedar authorizer
      const authorizer = new Cedar.Authorizer();

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

      // Load policy set (would be loaded from file or string)
      const policySet = Cedar.PolicySet.fromPolicies([]); // Empty for now

      // Authorize
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
    } catch (error: any) {
      // Fallback to RBAC if Cedar is unavailable
      console.warn(`Cedar evaluation failed: ${error.message}, falling back to RBAC`);
      return this.evaluateWithRBAC(request);
    }
  }

  /**
   * Evaluate with Cedar via HTTP API
   */
  private async evaluateWithCedarAPI(request: PDPRequest): Promise<PDPDecision> {
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
    } catch (error: any) {
      // Fallback to RBAC
      console.warn(`Cedar API evaluation failed: ${error.message}, falling back to RBAC`);
      return this.evaluateWithRBAC(request);
    }
  }

  /**
   * Generate cache key for request
   */
  private generateCacheKey(request: PDPRequest): string {
    return JSON.stringify({
      subjectId: request.subject.id,
      role: request.subject.attributes.role,
      resourceId: request.resource.id,
      resourceType: request.resource.type,
      context: request.context,
    });
  }

  /**
   * Clear policy cache
   */
  clearCache(): void {
    this.policyCache.clear();
  }
}

