/**
 * HIPAA (Health Insurance Portability and Accountability Act) Policy Template
 */

import { ABACPolicy } from '../../core/types';

export interface HIPAATemplateConfig {
  applicationName: string;
  coveredEntities?: string[];
  businessAssociates?: string[];
}

export function createHIPAATemplate(config: HIPAATemplateConfig): ABACPolicy[] {
  const policies: ABACPolicy[] = [];

  // Minimum necessary rule
  policies.push({
    id: 'hipaa-minimum-necessary',
    name: 'HIPAA Minimum Necessary Rule',
    description: 'Users can only access the minimum necessary PHI to perform their job functions',
    effect: 'allow',
    priority: 100,
    conditions: [
      {
        attribute: 'subject.role',
        operator: 'in',
        value: ['healthcare-provider', 'administrator', 'researcher'],
      },
      {
        attribute: 'resource.dataClassification',
        operator: 'equals',
        value: 'phi',
        logicalOperator: 'AND',
      },
    ],
  });

  // Access control for PHI
  policies.push({
    id: 'hipaa-phi-access-control',
    name: 'HIPAA PHI Access Control',
    description: 'Only authorized personnel can access PHI',
    effect: 'allow',
    priority: 200,
    conditions: [
      {
        attribute: 'subject.role',
        operator: 'in',
        value: ['healthcare-provider', 'administrator'],
      },
      {
        attribute: 'resource.dataClassification',
        operator: 'equals',
        value: 'phi',
        logicalOperator: 'AND',
      },
      {
        attribute: 'context.location',
        operator: 'in',
        value: ['hospital', 'clinic', 'secure-office'],
        logicalOperator: 'AND',
      },
    ],
  });

  // Audit logging requirement
  policies.push({
    id: 'hipaa-audit-logging',
    name: 'HIPAA Audit Logging Requirement',
    description: 'All PHI access must be logged',
    effect: 'allow',
    priority: 50,
    conditions: [
      {
        attribute: 'resource.dataClassification',
        operator: 'equals',
        value: 'phi',
      },
    ],
  });

  // Encryption requirement for PHI in transit
  policies.push({
    id: 'hipaa-encryption-transit',
    name: 'HIPAA Encryption in Transit',
    description: 'PHI must be encrypted when transmitted',
    effect: 'allow',
    priority: 300,
    conditions: [
      {
        attribute: 'resource.dataClassification',
        operator: 'equals',
        value: 'phi',
      },
      {
        attribute: 'context.encryption',
        operator: 'equals',
        value: true,
        logicalOperator: 'AND',
      },
    ],
  });

  // Business Associate Agreement requirement
  if (config.businessAssociates && config.businessAssociates.length > 0) {
    policies.push({
      id: 'hipaa-baa-requirement',
      name: 'HIPAA Business Associate Agreement',
      description: 'Business associates must have BAA in place to access PHI',
      effect: 'allow',
      priority: 250,
      conditions: [
        {
          attribute: 'subject.businessAssociate',
          operator: 'in',
          value: config.businessAssociates,
        },
        {
          attribute: 'subject.baaSigned',
          operator: 'equals',
          value: true,
          logicalOperator: 'AND',
        },
        {
          attribute: 'resource.dataClassification',
          operator: 'equals',
          value: 'phi',
          logicalOperator: 'AND',
        },
      ],
    });
  }

  // Deny access to PHI for unauthorized roles
  policies.push({
    id: 'hipaa-deny-unauthorized',
    name: 'HIPAA Deny Unauthorized Access',
    description: 'Deny access to PHI for unauthorized roles',
    effect: 'deny',
    priority: 400,
    conditions: [
      {
        attribute: 'subject.role',
        operator: 'notIn',
        value: ['healthcare-provider', 'administrator', 'researcher'],
      },
      {
        attribute: 'resource.dataClassification',
        operator: 'equals',
        value: 'phi',
        logicalOperator: 'AND',
      },
    ],
  });

  return policies;
}

export const HIPAA_TEMPLATE_DESCRIPTION = `
HIPAA (Health Insurance Portability and Accountability Act) Template

This template creates policies compliant with HIPAA regulations for protecting
Protected Health Information (PHI). It includes minimum necessary rules, access
controls, audit logging, encryption requirements, and business associate agreements.

Configuration variables:
- applicationName: Name of the application
- coveredEntities: Array of covered entity names (optional)
- businessAssociates: Array of business associate names (optional)

Example usage:
  heimdall template create hipaa --application-name "HealthApp" \\
    --covered-entities hospital,clinic \\
    --business-associates vendor1,vendor2
`;
