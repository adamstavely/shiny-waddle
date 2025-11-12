import { User, UserSimulationConfig } from '../core/types';
export declare class UserSimulator {
    private config;
    constructor(config: UserSimulationConfig);
    generateTestUsers(roles: string[]): Promise<User[]>;
    private createUser;
    private generateUserId;
    private getRoleAttributes;
    private generateDefaultWorkspaceMemberships;
    createCustomUser(role: string, customAttributes: Record<string, any>): User;
    generateUserVariations(baseRole: string, count: number): Promise<User[]>;
}
