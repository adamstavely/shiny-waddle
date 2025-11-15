/**
 * ABAC Attribute Propagation Tester
 * 
 * Tests attribute inheritance, propagation across systems, transformation, and consistency
 */

import { ABACAttribute } from './abac-attribute-validator';

export interface PropagationTestConfig {
  sourceSystem: string;
  targetSystems: string[];
  attributes: ABACAttribute[];
  transformationRules?: TransformationRule[];
}

export interface TransformationRule {
  sourceAttribute: string;
  targetAttribute: string;
  transformation: 'copy' | 'map' | 'derive' | 'aggregate';
  function?: string;
}

export interface PropagationTestResult {
  passed: boolean;
  propagationResults: Array<{
    source: string;
    target: string;
    attribute: string;
    propagated: boolean;
    transformed: boolean;
    consistent: boolean;
    latency: number;
  }>;
  consistencyIssues: ConsistencyIssue[];
}

export interface ConsistencyIssue {
  attribute: string;
  system: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface InheritanceResult {
  inherited: boolean;
  baseAttributes: string[];
  derivedAttributes: string[];
  conflicts: Array<{
    attribute: string;
    conflict: string;
  }>;
}

export interface SystemResult {
  systems: string[];
  allPropagated: boolean;
  issues: string[];
}

export interface TransformationResult {
  transformed: boolean;
  transformations: Array<{
    source: string;
    target: string;
    success: boolean;
  }>;
  issues: string[];
}

export interface ConsistencyResult {
  consistent: boolean;
  inconsistencies: Array<{
    attribute: string;
    system: string;
    value: any;
    expectedValue: any;
  }>;
}

export interface PerformanceResult {
  averageLatency: number;
  slowestPropagation: string;
  issues: string[];
}

export interface AuditResult {
  logged: boolean;
  auditTrail: Array<{
    timestamp: Date;
    attribute: string;
    source: string;
    target: string;
    action: string;
  }>;
  issues: string[];
}

export class ABACPropagationTester {
  /**
   * Test attribute propagation
   */
  async testAttributePropagation(
    config: PropagationTestConfig
  ): Promise<PropagationTestResult> {
    const propagationResults: PropagationTestResult['propagationResults'] = [];
    const consistencyIssues: ConsistencyIssue[] = [];

    // Test propagation to each target system
    for (const targetSystem of config.targetSystems) {
      for (const attribute of config.attributes) {
        const startTime = Date.now();

        // Simulate propagation
        const propagated = await this.simulatePropagation(
          config.sourceSystem,
          targetSystem,
          attribute
        );

        const latency = Date.now() - startTime;

        // Check if transformation is needed
        const transformed = this.checkTransformation(
          attribute,
          config.transformationRules
        );

        // Check consistency
        const consistent = await this.checkConsistency(
          config.sourceSystem,
          targetSystem,
          attribute
        );

        if (!consistent) {
          consistencyIssues.push({
            attribute: attribute.name,
            system: targetSystem,
            issue: 'Attribute value is inconsistent between systems',
            severity: 'high',
          });
        }

        propagationResults.push({
          source: config.sourceSystem,
          target: targetSystem,
          attribute: attribute.name,
          propagated,
          transformed,
          consistent,
          latency,
        });
      }
    }

    const allPropagated = propagationResults.every(r => r.propagated);
    const allConsistent = consistencyIssues.length === 0;

    return {
      passed: allPropagated && allConsistent,
      propagationResults,
      consistencyIssues,
    };
  }

  /**
   * Test attribute inheritance
   */
  async testAttributeInheritance(
    attributes: ABACAttribute[]
  ): Promise<InheritanceResult> {
    const baseAttributes: string[] = [];
    const derivedAttributes: string[] = [];
    const conflicts: InheritanceResult['conflicts'] = [];

    // Identify base and derived attributes
    for (const attr of attributes) {
      if (attr.source === 'ldap' || attr.source === 'database') {
        baseAttributes.push(attr.name);
      } else if (attr.source === 'custom' || attr.source === 'api') {
        derivedAttributes.push(attr.name);
      }
    }

    // Check for conflicts
    for (const baseAttr of baseAttributes) {
      for (const derivedAttr of derivedAttributes) {
        if (baseAttr === derivedAttr) {
          conflicts.push({
            attribute: baseAttr,
            conflict: 'Base and derived attributes have same name',
          });
        }
      }
    }

    return {
      inherited: baseAttributes.length > 0 && derivedAttributes.length > 0,
      baseAttributes,
      derivedAttributes,
      conflicts,
    };
  }

  /**
   * Validate propagation across systems
   */
  async validatePropagationAcrossSystems(
    config: PropagationTestConfig
  ): Promise<SystemResult> {
    const issues: string[] = [];
    let allPropagated = true;

    // Check if all target systems receive attributes
    for (const targetSystem of config.targetSystems) {
      const propagated = await this.checkSystemPropagation(
        config.sourceSystem,
        targetSystem,
        config.attributes
      );

      if (!propagated) {
        allPropagated = false;
        issues.push(`Attributes not propagated to ${targetSystem}`);
      }
    }

    // Check propagation order
    if (config.targetSystems.length > 1) {
      const orderValid = this.validatePropagationOrder(config.targetSystems);
      if (!orderValid) {
        issues.push('Propagation order may cause inconsistencies');
      }
    }

    return {
      systems: [config.sourceSystem, ...config.targetSystems],
      allPropagated,
      issues,
    };
  }

  /**
   * Test attribute transformation
   */
  async testAttributeTransformation(
    config: PropagationTestConfig
  ): Promise<TransformationResult> {
    const transformations: TransformationResult['transformations'] = [];
    const issues: string[] = [];

    if (!config.transformationRules || config.transformationRules.length === 0) {
      return {
        transformed: false,
        transformations: [],
        issues: ['No transformation rules configured'],
      };
    }

    // Test each transformation rule
    for (const rule of config.transformationRules) {
      const sourceAttr = config.attributes.find(a => a.name === rule.sourceAttribute);
      const targetAttr = config.attributes.find(a => a.name === rule.targetAttribute);

      if (!sourceAttr) {
        issues.push(`Source attribute ${rule.sourceAttribute} not found`);
        continue;
      }

      if (!targetAttr) {
        issues.push(`Target attribute ${rule.targetAttribute} not found`);
        continue;
      }

      // Test transformation
      const success = await this.testTransformation(rule, sourceAttr, targetAttr);

      transformations.push({
        source: rule.sourceAttribute,
        target: rule.targetAttribute,
        success,
      });

      if (!success) {
        issues.push(
          `Transformation from ${rule.sourceAttribute} to ${rule.targetAttribute} failed`
        );
      }
    }

    return {
      transformed: transformations.every(t => t.success),
      transformations,
      issues,
    };
  }

  /**
   * Validate attribute consistency
   */
  async validateAttributeConsistency(
    config: PropagationTestConfig
  ): Promise<ConsistencyResult> {
    const inconsistencies: ConsistencyResult['inconsistencies'] = [];

    // Check consistency across all systems
    for (const targetSystem of config.targetSystems) {
      for (const attribute of config.attributes) {
        const sourceValue = await this.getAttributeValue(
          config.sourceSystem,
          attribute
        );
        const targetValue = await this.getAttributeValue(targetSystem, attribute);

        if (sourceValue !== targetValue) {
          inconsistencies.push({
            attribute: attribute.name,
            system: targetSystem,
            value: targetValue,
            expectedValue: sourceValue,
          });
        }
      }
    }

    return {
      consistent: inconsistencies.length === 0,
      inconsistencies,
    };
  }

  /**
   * Test propagation performance
   */
  async testPropagationPerformance(
    config: PropagationTestConfig
  ): Promise<PerformanceResult> {
    const latencies: number[] = [];
    const issues: string[] = [];

    // Measure propagation latency for each attribute to each target
    for (const targetSystem of config.targetSystems) {
      for (const attribute of config.attributes) {
        const startTime = Date.now();
        await this.simulatePropagation(
          config.sourceSystem,
          targetSystem,
          attribute
        );
        const latency = Date.now() - startTime;
        latencies.push(latency);
      }
    }

    const averageLatency =
      latencies.length > 0
        ? latencies.reduce((a, b) => a + b, 0) / latencies.length
        : 0;

    if (averageLatency > 1000) {
      issues.push(`Average propagation latency (${averageLatency}ms) is high`);
    }

    const slowestPropagation = latencies.length > 0
      ? `Attribute propagation took ${Math.max(...latencies)}ms`
      : 'N/A';

    return {
      averageLatency,
      slowestPropagation,
      issues,
    };
  }

  /**
   * Validate propagation audit trail
   */
  async validatePropagationAuditTrail(
    config: PropagationTestConfig
  ): Promise<AuditResult> {
    const issues: string[] = [];
    const auditTrail: AuditResult['auditTrail'] = [];

    // Simulate audit trail generation
    for (const targetSystem of config.targetSystems) {
      for (const attribute of config.attributes) {
        auditTrail.push({
          timestamp: new Date(),
          attribute: attribute.name,
          source: config.sourceSystem,
          target: targetSystem,
          action: 'propagated',
        });
      }
    }

    // Check if audit trail is complete
    const expectedEntries =
      config.targetSystems.length * config.attributes.length;
    if (auditTrail.length < expectedEntries) {
      issues.push(
        `Audit trail incomplete: ${auditTrail.length}/${expectedEntries} entries`
      );
    }

    return {
      logged: auditTrail.length > 0,
      auditTrail,
      issues,
    };
  }

  /**
   * Simulate attribute propagation
   */
  private async simulatePropagation(
    source: string,
    target: string,
    attribute: ABACAttribute
  ): Promise<boolean> {
    // Simulate propagation delay based on source type
    const delays: Record<string, number> = {
      ldap: 50,
      database: 30,
      api: 100,
      jwt: 10,
      custom: 20,
    };

    const delay = delays[attribute.source] || 50;
    await new Promise(resolve => setTimeout(resolve, delay));

    // Simulate success (90% success rate)
    return Math.random() > 0.1;
  }

  /**
   * Check if transformation is needed
   */
  private checkTransformation(
    attribute: ABACAttribute,
    rules?: TransformationRule[]
  ): boolean {
    if (!rules) {
      return false;
    }

    return rules.some(
      rule => rule.sourceAttribute === attribute.name
    );
  }

  /**
   * Check consistency between systems
   */
  private async checkConsistency(
    source: string,
    target: string,
    attribute: ABACAttribute
  ): Promise<boolean> {
    // Simulate consistency check
    // In real implementation, would compare actual values
    return Math.random() > 0.2; // 80% consistent
  }

  /**
   * Check system propagation
   */
  private async checkSystemPropagation(
    source: string,
    target: string,
    attributes: ABACAttribute[]
  ): Promise<boolean> {
    // Check if all attributes are propagated
    for (const attribute of attributes) {
      const propagated = await this.simulatePropagation(source, target, attribute);
      if (!propagated) {
        return false;
      }
    }
    return true;
  }

  /**
   * Validate propagation order
   */
  private validatePropagationOrder(systems: string[]): boolean {
    // Check if propagation order makes sense
    // Typically should be: source -> staging -> production
    const order = ['dev', 'staging', 'prod'];
    let lastIndex = -1;

    for (const system of systems) {
      const index = order.findIndex(o => system.toLowerCase().includes(o));
      if (index !== -1) {
        if (index < lastIndex) {
          return false; // Out of order
        }
        lastIndex = index;
      }
    }

    return true;
  }

  /**
   * Test transformation
   */
  private async testTransformation(
    rule: TransformationRule,
    sourceAttr: ABACAttribute,
    targetAttr: ABACAttribute
  ): Promise<boolean> {
    // Test transformation based on type
    switch (rule.transformation) {
      case 'copy':
        return sourceAttr.type === targetAttr.type;

      case 'map':
        // Mapping should work if types are compatible
        return this.areTypesCompatible(sourceAttr.type, targetAttr.type);

      case 'derive':
        // Derivation requires a function
        return !!rule.function;

      case 'aggregate':
        // Aggregation requires array source
        return sourceAttr.type === 'array';

      default:
        return false;
    }
  }

  /**
   * Check if types are compatible
   */
  private areTypesCompatible(type1: string, type2: string): boolean {
    if (type1 === type2) {
      return true;
    }

    // String can be converted to number in some cases
    if ((type1 === 'string' && type2 === 'number') || (type1 === 'number' && type2 === 'string')) {
      return true;
    }

    return false;
  }

  /**
   * Get attribute value from system
   */
  private async getAttributeValue(
    system: string,
    attribute: ABACAttribute
  ): Promise<any> {
    // Simulate getting attribute value
    // In real implementation, would query the actual system
    return `value-from-${system}`;
  }
}

