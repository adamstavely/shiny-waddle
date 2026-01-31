import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Policy, PolicyVersion } from '../../entities/policy.entity';
import { PolicyType, PolicyStatus, PolicyEffect, RBACRule, ABACCondition } from '../../dto/create-policy.dto';
import { PoliciesService } from '../../policies.service';
import { PolicyBuilderState, PolicyFormData, RBACRuleFormData, ABACConditionFormData } from '../entities/policy-builder-state.entity';
import { PolicyTemplate } from '../entities/policy-template.entity';
import { PolicyTemplateService } from './policy-template.service';

@Injectable()
export class PolicyBuilderService {
  private builderStates: Map<string, PolicyBuilderState> = new Map();

  constructor(
    private readonly policiesService: PoliciesService,
    private readonly templateService: PolicyTemplateService,
  ) {}

  /**
   * Convert form data to Policy entity
   */
  formDataToPolicy(formData: PolicyFormData, policyId?: string): Policy {
    const policy: Policy = {
      id: policyId || uuidv4(),
      name: formData.name,
      description: formData.description,
      type: formData.rules ? PolicyType.RBAC : PolicyType.ABAC,
      version: formData.version,
      status: formData.status || PolicyStatus.DRAFT,
      effect: formData.effect,
      applicationId: formData.applicationId,
      versions: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    if (formData.rules && formData.rules.length > 0) {
      // RBAC policy
      policy.rules = formData.rules.map(rule => this.convertRBACRule(rule));
      policy.ruleCount = policy.rules.length;
    } else if (formData.conditions && formData.conditions.length > 0) {
      // ABAC policy
      policy.priority = formData.priority || 100;
      policy.conditions = formData.conditions.map(cond => this.convertABACCondition(cond));
    }

    return policy;
  }

  /**
   * Convert Policy entity to form data
   */
  policyToFormData(policy: Policy): PolicyFormData {
    const formData: PolicyFormData = {
      name: policy.name,
      description: policy.description,
      version: policy.version,
      status: policy.status,
      effect: policy.effect || PolicyEffect.ALLOW,
      applicationId: policy.applicationId,
    };

    if (policy.type === PolicyType.RBAC && policy.rules) {
      formData.rules = policy.rules.map(rule => this.convertRBACRuleToForm(rule));
    } else if (policy.type === PolicyType.ABAC && policy.conditions) {
      formData.priority = policy.priority;
      formData.conditions = policy.conditions.map(cond => this.convertABACConditionToForm(cond));
    }

    return formData;
  }

  /**
   * Create a new builder state
   */
  createBuilderState(policyType: PolicyType, policyId?: string): PolicyBuilderState {
    const stateId = uuidv4();
    const totalSteps = 5; // Basic info, policy definition, review

    let formData: PolicyFormData = {
      name: '',
      description: '',
      version: '1.0.0',
      status: PolicyStatus.DRAFT,
      effect: PolicyEffect.ALLOW,
    };

    // If editing existing policy, load it
    if (policyId) {
      const policy = this.policiesService.findOne(policyId);
      if (!policy) {
        throw new NotFoundException(`Policy with ID "${policyId}" not found`);
      }
      formData = this.policyToFormData(policy);
    } else {
      // Initialize based on policy type
      if (policyType === PolicyType.RBAC) {
        formData.rules = [];
      } else {
        formData.conditions = [];
        formData.priority = 100;
      }
    }

    const state: PolicyBuilderState = {
      id: stateId,
      policyId,
      currentStep: 1,
      totalSteps,
      policyType: policyType as 'rbac' | 'abac',
      formData,
      jsonData: JSON.stringify(this.formDataToPolicy(formData, policyId), null, 2),
      validationErrors: [],
      lastSynced: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.builderStates.set(stateId, state);
    return state;
  }

  /**
   * Update builder state
   */
  updateBuilderState(stateId: string, updates: Partial<PolicyBuilderState>): PolicyBuilderState {
    const state = this.builderStates.get(stateId);
    if (!state) {
      throw new NotFoundException(`Builder state with ID "${stateId}" not found`);
    }

    const updatedState: PolicyBuilderState = {
      ...state,
      ...updates,
      updatedAt: new Date(),
    };

    // If formData or jsonData changed, sync them
    if (updates.formData) {
      updatedState.jsonData = JSON.stringify(
        this.formDataToPolicy(updates.formData, state.policyId),
        null,
        2
      );
      updatedState.lastSynced = new Date();
    } else if (updates.jsonData) {
      try {
        const policy = JSON.parse(updates.jsonData) as Policy;
        updatedState.formData = this.policyToFormData(policy);
        updatedState.lastSynced = new Date();
      } catch (error) {
        throw new BadRequestException(`Invalid JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    this.builderStates.set(stateId, updatedState);
    return updatedState;
  }

  /**
   * Get builder state
   */
  getBuilderState(stateId: string): PolicyBuilderState {
    const state = this.builderStates.get(stateId);
    if (!state) {
      throw new NotFoundException(`Builder state with ID "${stateId}" not found`);
    }
    return state;
  }

  /**
   * Apply template to builder state
   */
  applyTemplate(stateId: string, templateId: string): PolicyBuilderState {
    const state = this.getBuilderState(stateId);
    const template = this.templateService.findOne(templateId);
    
    if (!template) {
      throw new NotFoundException(`Template with ID "${templateId}" not found`);
    }

    if (template.policyType !== state.policyType) {
      throw new BadRequestException(`Template type "${template.policyType}" does not match builder state type "${state.policyType}"`);
    }

    // Merge template with existing form data (preserve name, description if set)
    const mergedFormData: PolicyFormData = {
      ...template.template,
      name: state.formData.name || template.template.name,
      description: state.formData.description || template.template.description,
      version: state.formData.version || template.template.version,
    };

    return this.updateBuilderState(stateId, {
      formData: mergedFormData,
      currentStep: 2, // Move to policy definition step
    });
  }

  /**
   * Create policy from builder state
   */
  async createPolicyFromBuilder(stateId: string): Promise<Policy> {
    const state = this.getBuilderState(stateId);
    const policy = this.formDataToPolicy(state.formData);

    // Create policy via existing service
    const createdPolicy = await this.policiesService.create({
      name: policy.name,
      description: policy.description,
      type: policy.type,
      version: policy.version,
      status: policy.status,
      effect: policy.effect,
      priority: policy.priority,
      rules: policy.rules,
      conditions: policy.conditions,
      applicationId: policy.applicationId,
    });

    // Clean up builder state
    this.builderStates.delete(stateId);

    return createdPolicy;
  }

  /**
   * Update existing policy from builder state
   */
  async updatePolicyFromBuilder(policyId: string, stateId: string): Promise<Policy> {
    const state = this.getBuilderState(stateId);
    const existingPolicy = this.policiesService.findOne(policyId);
    
    if (!existingPolicy) {
      throw new NotFoundException(`Policy with ID "${policyId}" not found`);
    }

    const updatedPolicy = this.formDataToPolicy(state.formData, policyId);
    
    // Update policy via existing service
    const result = await this.policiesService.update(policyId, {
      name: updatedPolicy.name,
      description: updatedPolicy.description,
      version: updatedPolicy.version,
      status: updatedPolicy.status,
      effect: updatedPolicy.effect,
      priority: updatedPolicy.priority,
      rules: updatedPolicy.rules,
      conditions: updatedPolicy.conditions,
      applicationId: updatedPolicy.applicationId,
    });

    // Clean up builder state
    this.builderStates.delete(stateId);

    return result;
  }

  // Private helper methods

  private convertRBACRule(ruleForm: RBACRuleFormData): RBACRule {
    const conditions: Record<string, any> = {
      'subject.role': ruleForm.role,
    };

    if (ruleForm.resourceType) {
      conditions['resource.type'] = ruleForm.resourceType;
    }

    if (ruleForm.resourceSensitivity && ruleForm.resourceSensitivity.length > 0) {
      conditions['resource.sensitivity'] = ruleForm.resourceSensitivity.length === 1 
        ? ruleForm.resourceSensitivity[0] 
        : ruleForm.resourceSensitivity;
    }

    if (ruleForm.contextConditions) {
      Object.assign(conditions, ruleForm.contextConditions);
    }

    return {
      id: ruleForm.id,
      description: ruleForm.description,
      effect: ruleForm.effect,
      conditions,
    };
  }

  private convertRBACRuleToForm(rule: RBACRule): RBACRuleFormData {
    const role = rule.conditions['subject.role'] as string;
    const resourceType = rule.conditions['resource.type'] as string | undefined;
    const resourceSensitivity = rule.conditions['resource.sensitivity'];
    const sensitivityArray = Array.isArray(resourceSensitivity) 
      ? resourceSensitivity 
      : resourceSensitivity ? [resourceSensitivity] : undefined;

    const contextConditions: Record<string, any> = {};
    Object.keys(rule.conditions).forEach(key => {
      if (!['subject.role', 'resource.type', 'resource.sensitivity'].includes(key)) {
        contextConditions[key] = rule.conditions[key];
      }
    });

    return {
      id: rule.id,
      description: rule.description,
      effect: rule.effect,
      role: role || '',
      resourceType,
      resourceSensitivity: sensitivityArray as string[] | undefined,
      contextConditions: Object.keys(contextConditions).length > 0 ? contextConditions : undefined,
    };
  }

  private convertABACCondition(condForm: ABACConditionFormData): ABACCondition {
    return {
      attribute: condForm.attribute,
      operator: condForm.operator,
      value: Array.isArray(condForm.value) 
        ? condForm.value.join(',') 
        : String(condForm.value),
      logicalOperator: condForm.logicalOperator,
    };
  }

  private convertABACConditionToForm(cond: ABACCondition): ABACConditionFormData {
    const value = cond.value.includes(',') 
      ? cond.value.split(',').map(v => v.trim())
      : cond.value;

    return {
      id: uuidv4(), // Generate ID for form
      attribute: cond.attribute,
      operator: cond.operator as ABACConditionFormData['operator'],
      value: value as string | string[],
      logicalOperator: cond.logicalOperator as 'AND' | 'OR' | undefined,
    };
  }
}
