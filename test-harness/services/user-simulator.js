"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserSimulator = void 0;
class UserSimulator {
    constructor(config) {
        this.config = config;
    }
    async generateTestUsers(roles) {
        const users = [];
        for (const role of roles) {
            const user = this.createUser(role);
            users.push(user);
        }
        return users;
    }
    createUser(role) {
        const baseAttributes = this.config.attributes || {};
        const roleSpecificAttributes = this.getRoleAttributes(role);
        return {
            id: this.generateUserId(role),
            email: `${role}@test.example.com`,
            role: role,
            attributes: {
                ...baseAttributes,
                ...roleSpecificAttributes,
            },
            workspaceMemberships: this.config.workspaceMemberships || this.generateDefaultWorkspaceMemberships(role),
        };
    }
    generateUserId(role) {
        return `test-user-${role}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
    getRoleAttributes(role) {
        const roleAttributes = {
            admin: {
                department: 'IT',
                clearanceLevel: 'high',
                canExportData: true,
                canModifySchemas: true,
                abacAttributes: {
                    department: 'IT',
                    clearanceLevel: 'high',
                    projectAccess: ['*'],
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
    generateDefaultWorkspaceMemberships(role) {
        const workspaceRoleMap = {
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
    createCustomUser(role, customAttributes) {
        const baseUser = this.createUser(role);
        return {
            ...baseUser,
            attributes: {
                ...baseUser.attributes,
                ...customAttributes,
            },
        };
    }
    async generateUserVariations(baseRole, count) {
        const users = [];
        for (let i = 0; i < count; i++) {
            const user = this.createUser(baseRole);
            user.id = `${user.id}-variation-${i}`;
            user.email = `${baseRole}${i}@test.example.com`;
            users.push(user);
        }
        return users;
    }
}
exports.UserSimulator = UserSimulator;
//# sourceMappingURL=user-simulator.js.map