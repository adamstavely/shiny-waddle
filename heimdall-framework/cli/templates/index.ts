/**
 * Template Registry
 * Central registry for all policy templates
 */

import { ABACPolicy } from '../../core/types';
import { createRBACTemplate, RBACTemplateConfig } from './rbac-template';
import { createABACTemplate, ABACTemplateConfig } from './abac-template';
import { createHIPAATemplate, HIPAATemplateConfig } from './hipaa-template';
import { createGDPRTemplate, GDPRTemplateConfig } from './gdpr-template';
import { RBAC_TEMPLATE_DESCRIPTION } from './rbac-template';
import { ABAC_TEMPLATE_DESCRIPTION } from './abac-template';
import { HIPAA_TEMPLATE_DESCRIPTION } from './hipaa-template';
import { GDPR_TEMPLATE_DESCRIPTION } from './gdpr-template';

export type TemplateName = 'rbac' | 'abac' | 'hipaa' | 'gdpr';
export type TemplateConfig = RBACTemplateConfig | ABACTemplateConfig | HIPAATemplateConfig | GDPRTemplateConfig;

export interface TemplateInfo {
  name: string;
  description: string;
  create: (config: TemplateConfig) => ABACPolicy[];
}

export const TEMPLATES: Record<TemplateName, TemplateInfo> = {
  rbac: {
    name: 'RBAC',
    description: 'Role-Based Access Control template',
    create: (config) => createRBACTemplate(config as RBACTemplateConfig),
  },
  abac: {
    name: 'ABAC',
    description: 'Attribute-Based Access Control template',
    create: (config) => createABACTemplate(config as ABACTemplateConfig),
  },
  hipaa: {
    name: 'HIPAA',
    description: 'HIPAA compliance template for healthcare data',
    create: (config) => createHIPAATemplate(config as HIPAATemplateConfig),
  },
  gdpr: {
    name: 'GDPR',
    description: 'GDPR compliance template for EU personal data',
    create: (config) => createGDPRTemplate(config as GDPRTemplateConfig),
  },
};

export const TEMPLATE_DESCRIPTIONS: Record<TemplateName, string> = {
  rbac: RBAC_TEMPLATE_DESCRIPTION,
  abac: ABAC_TEMPLATE_DESCRIPTION,
  hipaa: HIPAA_TEMPLATE_DESCRIPTION,
  gdpr: GDPR_TEMPLATE_DESCRIPTION,
};

export function listTemplates(): TemplateName[] {
  return Object.keys(TEMPLATES) as TemplateName[];
}

export function getTemplate(name: TemplateName): TemplateInfo | undefined {
  return TEMPLATES[name];
}

export function getTemplateDescription(name: TemplateName): string {
  return TEMPLATE_DESCRIPTIONS[name] || '';
}
