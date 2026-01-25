/**
 * RBAC (Role-Based Access Control) Policy Template
 */

import { ABACPolicy } from '../../core/types';

export interface RBACTemplateConfig {
  applicationName: string;
  roles: string[];
  resources: string[];
  actions: string[];
}

export function createRBACTemplate(config: RBACTemplateConfig): ABACPolicy[] {
  const policies: ABACPolicy[] = [];

  // Create a policy for each role
  for (const role of config.roles) {
    // Admin role gets full access
    if (role === 'admin') {
      policies.push({
        id: `rbac-${role}-full-access`,
        name: `${role.charAt(0).toUpperCase() + role.slice(1)} Full Access`,
        description: `${role.charAt(0).toUpperCase() + role.slice(1)} users have full access to all resources`,
        effect: 'allow',
        priority: 100,
        conditions: [
          {
            attribute: 'subject.role',
            operator: 'equals',
            value: role,
          },
        ],
      });
    } else {
      // Other roles get access based on their role
      for (const resource of config.resources) {
        policies.push({
          id: `rbac-${role}-${resource}`,
          name: `${role.charAt(0).toUpperCase() + role.slice(1)} Access to ${resource}`,
          description: `${role.charAt(0).toUpperCase() + role.slice(1)} users can access ${resource} resources`,
          effect: 'allow',
          priority: 50,
          conditions: [
            {
              attribute: 'subject.role',
              operator: 'equals',
              value: role,
            },
            {
              attribute: 'resource.type',
              operator: 'equals',
              value: resource,
              logicalOperator: 'AND',
            },
          ],
        });
      }
    }
  }

  return policies;
}

export const RBAC_TEMPLATE_DESCRIPTION = `
RBAC (Role-Based Access Control) Template

This template creates policies based on user roles. Each role is assigned
permissions to specific resources.

Configuration variables:
- applicationName: Name of the application
- roles: Array of role names (e.g., ['admin', 'user', 'viewer'])
- resources: Array of resource types (e.g., ['dataset', 'report', 'database'])
- actions: Array of actions (e.g., ['read', 'write', 'delete'])

Example usage:
  heimdall template create rbac --application-name "MyApp" \\
    --roles admin,user,viewer \\
    --resources dataset,report \\
    --actions read,write
`;
