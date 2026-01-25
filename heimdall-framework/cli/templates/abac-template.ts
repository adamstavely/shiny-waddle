/**
 * ABAC (Attribute-Based Access Control) Policy Template
 */

import { ABACPolicy } from '../../core/types';

export interface ABACTemplateConfig {
  applicationName: string;
  departments?: string[];
  clearanceLevels?: string[];
  dataClassifications?: string[];
  projects?: string[];
}

export function createABACTemplate(config: ABACTemplateConfig): ABACPolicy[] {
  const policies: ABACPolicy[] = [];

  // Department-based access
  if (config.departments && config.departments.length > 0) {
    policies.push({
      id: 'abac-department-match',
      name: 'Department Match Policy',
      description: 'Users can access resources from their own department',
      effect: 'allow',
      priority: 100,
      conditions: [
        {
          attribute: 'subject.department',
          operator: 'equals',
          value: '{{resource.department}}',
        },
      ],
    });
  }

  // Clearance level-based access
  if (config.clearanceLevels && config.clearanceLevels.length > 0) {
    policies.push({
      id: 'abac-clearance-level-required',
      name: 'Clearance Level Requirement',
      description: 'Users must have sufficient clearance level for classified resources',
      effect: 'allow',
      priority: 200,
      conditions: [
        {
          attribute: 'subject.clearanceLevel',
          operator: 'in',
          value: config.clearanceLevels,
        },
        {
          attribute: 'resource.dataClassification',
          operator: 'in',
          value: config.dataClassifications || ['confidential', 'restricted', 'top-secret'],
          logicalOperator: 'AND',
        },
      ],
    });
  }

  // Project-based access
  if (config.projects && config.projects.length > 0) {
    policies.push({
      id: 'abac-project-access',
      name: 'Project Access Policy',
      description: 'Users can access resources from projects they have access to',
      effect: 'allow',
      priority: 150,
      conditions: [
        {
          attribute: 'subject.projectAccess',
          operator: 'contains',
          value: '{{resource.project}}',
        },
      ],
    });
  }

  // Location-based access
  policies.push({
    id: 'abac-location-based',
    name: 'Location-Based Access',
    description: 'Users can only access resources from approved locations',
    effect: 'allow',
    priority: 120,
    conditions: [
      {
        attribute: 'context.location',
        operator: 'in',
        value: ['headquarters', 'office', 'research-lab'],
      },
      {
        attribute: 'resource.dataClassification',
        operator: 'in',
        value: config.dataClassifications || ['confidential', 'restricted'],
        logicalOperator: 'AND',
      },
    ],
  });

  // Time-based restriction
  policies.push({
    id: 'abac-time-based-restriction',
    name: 'Time-Based Access Restriction',
    description: 'Restricted resources only accessible during business hours',
    effect: 'allow',
    priority: 130,
    conditions: [
      {
        attribute: 'context.timeOfDay',
        operator: 'regex',
        value: '^(0[8-9]|1[0-8]):',
      },
      {
        attribute: 'resource.dataClassification',
        operator: 'equals',
        value: 'restricted',
        logicalOperator: 'AND',
      },
    ],
  });

  return policies;
}

export const ABAC_TEMPLATE_DESCRIPTION = `
ABAC (Attribute-Based Access Control) Template

This template creates policies based on user attributes, resource attributes,
and context. It supports department matching, clearance levels, project access,
location-based access, and time-based restrictions.

Configuration variables:
- applicationName: Name of the application
- departments: Array of department names (optional)
- clearanceLevels: Array of clearance levels (optional, e.g., ['high', 'top-secret'])
- dataClassifications: Array of data classifications (optional, e.g., ['confidential', 'restricted'])
- projects: Array of project names (optional)

Example usage:
  heimdall template create abac --application-name "MyApp" \\
    --departments engineering,research,finance \\
    --clearance-levels high,top-secret \\
    --data-classifications confidential,restricted \\
    --projects alpha,beta
`;
