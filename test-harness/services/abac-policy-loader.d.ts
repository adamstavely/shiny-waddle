import { ABACPolicy } from '../core/types';
export declare class ABACPolicyLoader {
    loadPoliciesFromFile(filePath: string): Promise<ABACPolicy[]>;
    loadPoliciesFromDirectory(dirPath: string): Promise<ABACPolicy[]>;
    private validatePolicy;
    createDefaultABACPolicies(): ABACPolicy[];
}
