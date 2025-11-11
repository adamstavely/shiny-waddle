/**
 * User Simulator Service
 * 
 * Simulates users with different roles/attributes for testing
 */

import { User, WorkspaceMembership, UserSimulationConfig } from '../core/types';

export class UserSimulator {
  private config: UserSimulationConfig;

  constructor(config: UserSimulationConfig) {
    this.config = config;
  }

  /**
   * Generate test users with specified roles
   */
  async generateTestUsers(roles: string[]): Promise<User[]> {
    const users: User[] = [];

    for (const role of roles) {
      const user = this.createUser(role);
      users.push(user);
    }

    return users;
  }

  /**
   * Create a user with a specific role
   */
  private createUser(role: string): User {
    const baseAttributes = this.config.attributes || {};
    const roleSpecificAttributes = this.getRoleAttributes(role);

    return {
      id: this.generateUserId(role),
      email: `${role}@test.example.com`,
      role: role as User['role'],
      attributes: {
        ...baseAttributes,
        ...roleSpecificAttributes,
      },
      workspaceMemberships: this.config.workspaceMemberships || this.generateDefaultWorkspaceMemberships(role),
    };
  }

  /**
   * Generate a unique user ID for a role
   */
  private generateUserId(role: string): string {
    return `test-user-${role}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get role-specific attributes (including ABAC attributes)
   */
  private getRoleAttributes(role: string): Record<string, any> {
    const roleAttributes: Record<string, Record<string, any>> = {
      admin: {
        department: 'IT',
        clearanceLevel: 'high',
        canExportData: true,
        canModifySchemas: true,
        // ABAC attributes
        abacAttributes: {
          department: 'IT',
          clearanceLevel: 'high',
          projectAccess: ['*'], // All projects
          dataClassification: ['public', 'internal', 'confidential', 'restricted', 'top-secret'],
          location: 'headquarters',
          employmentType: 'full-time',
          certifications: ['security-admin', 'data-governance'],
        },
      },
      researcher: {
        department: 'Research',
        clearanceLevel: 'medium',
        canExportData: false,
        canModifySchemas: false,
        researchAreas: ['data-science', 'analytics'],
        // ABAC attributes
        abacAttributes: {
          department: 'Research',
          clearanceLevel: 'medium',
          projectAccess: ['project-alpha', 'project-beta'],
          dataClassification: ['public', 'internal', 'confidential'],
          location: 'research-lab',
          employmentType: 'full-time',
          certifications: ['data-science'],
        },
      },
      analyst: {
        department: 'Analytics',
        clearanceLevel: 'medium',
        canExportData: false,
        canModifySchemas: false,
        analysisTools: ['sql', 'python'],
        // ABAC attributes
        abacAttributes: {
          department: 'Analytics',
          clearanceLevel: 'medium',
          projectAccess: ['project-alpha'],
          dataClassification: ['public', 'internal'],
          location: 'office',
          employmentType: 'full-time',
          certifications: ['sql-analyst'],
        },
      },
      viewer: {
        department: 'General',
        clearanceLevel: 'low',
        canExportData: false,
        canModifySchemas: false,
        readOnly: true,
        // ABAC attributes
        abacAttributes: {
          department: 'General',
          clearanceLevel: 'low',
          projectAccess: [],
          dataClassification: ['public'],
          location: 'remote',
          employmentType: 'contractor',
          certifications: [],
        },
      },
    };

    return roleAttributes[role] || {};
  }

  /**
   * Generate default workspace memberships based on role
   */
  private generateDefaultWorkspaceMemberships(role: string): WorkspaceMembership[] {
    const workspaceRoleMap: Record<string, 'owner' | 'editor' | 'viewer'> = {
      admin: 'owner',
      researcher: 'editor',
      analyst: 'editor',
      viewer: 'viewer',
    };

    return [
      {
        workspaceId: 'default-workspace',
        role: workspaceRoleMap[role] || 'viewer',
      },
    ];
  }

  /**
   * Create a user with custom attributes
   */
  createCustomUser(role: string, customAttributes: Record<string, any>): User {
    const baseUser = this.createUser(role);
    return {
      ...baseUser,
      attributes: {
        ...baseUser.attributes,
        ...customAttributes,
      },
    };
  }

  /**
   * Create multiple users with variations
   */
  async generateUserVariations(baseRole: string, count: number): Promise<User[]> {
    const users: User[] = [];

    for (let i = 0; i < count; i++) {
      const user = this.createUser(baseRole);
      user.id = `${user.id}-variation-${i}`;
      user.email = `${baseRole}${i}@test.example.com`;
      users.push(user);
    }

    return users;
  }
}

