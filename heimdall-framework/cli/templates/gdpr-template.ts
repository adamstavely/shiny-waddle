/**
 * GDPR (General Data Protection Regulation) Policy Template
 */

import { ABACPolicy } from '../../core/types';

export interface GDPRTemplateConfig {
  applicationName: string;
  dataControllers?: string[];
  dataProcessors?: string[];
  euMemberStates?: string[];
}

export function createGDPRTemplate(config: GDPRTemplateConfig): ABACPolicy[] {
  const policies: ABACPolicy[] = [];

  // Right to access (Article 15)
  policies.push({
    id: 'gdpr-right-to-access',
    name: 'GDPR Right to Access',
    description: 'Data subjects have the right to access their personal data',
    effect: 'allow',
    priority: 100,
    conditions: [
      {
        attribute: 'subject.dataSubject',
        operator: 'equals',
        value: true,
      },
      {
        attribute: 'resource.dataSubjectId',
        operator: 'equals',
        value: '{{subject.id}}',
        logicalOperator: 'AND',
      },
      {
        attribute: 'action',
        operator: 'equals',
        value: 'read',
        logicalOperator: 'AND',
      },
    ],
  });

  // Right to erasure (Article 17 - Right to be forgotten)
  policies.push({
    id: 'gdpr-right-to-erasure',
    name: 'GDPR Right to Erasure',
    description: 'Data subjects have the right to request erasure of their personal data',
    effect: 'allow',
    priority: 150,
    conditions: [
      {
        attribute: 'subject.dataSubject',
        operator: 'equals',
        value: true,
      },
      {
        attribute: 'resource.dataSubjectId',
        operator: 'equals',
        value: '{{subject.id}}',
        logicalOperator: 'AND',
      },
      {
        attribute: 'action',
        operator: 'equals',
        value: 'delete',
        logicalOperator: 'AND',
      },
      {
        attribute: 'subject.erasureRequested',
        operator: 'equals',
        value: true,
        logicalOperator: 'AND',
      },
    ],
  });

  // Data minimization (Article 5)
  policies.push({
    id: 'gdpr-data-minimization',
    name: 'GDPR Data Minimization',
    description: 'Only collect and process personal data that is necessary',
    effect: 'allow',
    priority: 200,
    conditions: [
      {
        attribute: 'subject.role',
        operator: 'in',
        value: ['data-controller', 'data-processor'],
      },
      {
        attribute: 'resource.personalData',
        operator: 'equals',
        value: true,
        logicalOperator: 'AND',
      },
      {
        attribute: 'action',
        operator: 'in',
        value: ['read', 'process'],
        logicalOperator: 'AND',
      },
    ],
  });

  // Purpose limitation (Article 5)
  policies.push({
    id: 'gdpr-purpose-limitation',
    name: 'GDPR Purpose Limitation',
    description: 'Personal data can only be processed for specified purposes',
    effect: 'allow',
    priority: 180,
    conditions: [
      {
        attribute: 'resource.personalData',
        operator: 'equals',
        value: true,
      },
      {
        attribute: 'resource.processingPurpose',
        operator: 'in',
        value: ['consent', 'contract', 'legal-obligation', 'vital-interests', 'public-task', 'legitimate-interests'],
        logicalOperator: 'AND',
      },
    ],
  });

  // Cross-border data transfer restrictions (Article 44-49)
  if (config.euMemberStates && config.euMemberStates.length > 0) {
    policies.push({
      id: 'gdpr-cross-border-transfer',
      name: 'GDPR Cross-Border Transfer Restriction',
      description: 'Personal data can only be transferred outside EU with adequate safeguards',
      effect: 'allow',
      priority: 250,
      conditions: [
        {
          attribute: 'resource.personalData',
          operator: 'equals',
          value: true,
        },
        {
          attribute: 'context.location',
          operator: 'in',
          value: config.euMemberStates,
          logicalOperator: 'AND',
        },
        {
          attribute: 'context.transferSafeguards',
          operator: 'equals',
          value: true,
          logicalOperator: 'AND',
        },
      ],
    });
  }

  // Consent requirement (Article 6)
  policies.push({
    id: 'gdpr-consent-requirement',
    name: 'GDPR Consent Requirement',
    description: 'Personal data processing requires explicit consent unless legal basis exists',
    effect: 'allow',
    priority: 300,
    conditions: [
      {
        attribute: 'resource.personalData',
        operator: 'equals',
        value: true,
      },
      {
        attribute: 'resource.consentGiven',
        operator: 'equals',
        value: true,
        logicalOperator: 'OR',
      },
      {
        attribute: 'resource.legalBasis',
        operator: 'in',
        value: ['contract', 'legal-obligation', 'vital-interests', 'public-task', 'legitimate-interests'],
        logicalOperator: 'OR',
      },
    ],
  });

  // Data breach notification (Article 33)
  policies.push({
    id: 'gdpr-breach-notification',
    name: 'GDPR Breach Notification',
    description: 'Data breaches must be reported within 72 hours',
    effect: 'allow',
    priority: 50,
    conditions: [
      {
        attribute: 'resource.personalData',
        operator: 'equals',
        value: true,
      },
      {
        attribute: 'context.breachDetected',
        operator: 'equals',
        value: true,
        logicalOperator: 'AND',
      },
    ],
  });

  // Deny unauthorized access to personal data
  policies.push({
    id: 'gdpr-deny-unauthorized',
    name: 'GDPR Deny Unauthorized Access',
    description: 'Deny access to personal data without proper authorization',
    effect: 'deny',
    priority: 400,
    conditions: [
      {
        attribute: 'resource.personalData',
        operator: 'equals',
        value: true,
      },
      {
        attribute: 'subject.role',
        operator: 'notIn',
        value: ['data-controller', 'data-processor', 'data-subject'],
        logicalOperator: 'AND',
      },
    ],
  });

  return policies;
}

export const GDPR_TEMPLATE_DESCRIPTION = `
GDPR (General Data Protection Regulation) Template

This template creates policies compliant with GDPR regulations for protecting
personal data of EU citizens. It includes rights to access and erasure, data
minimization, purpose limitation, cross-border transfer restrictions, consent
requirements, and breach notification.

Configuration variables:
- applicationName: Name of the application
- dataControllers: Array of data controller names (optional)
- dataProcessors: Array of data processor names (optional)
- euMemberStates: Array of EU member state codes (optional, e.g., ['DE', 'FR', 'IT'])

Example usage:
  heimdall template create gdpr --application-name "DataApp" \\
    --data-controllers company1,company2 \\
    --data-processors vendor1,vendor2 \\
    --eu-member-states DE,FR,IT
`;
