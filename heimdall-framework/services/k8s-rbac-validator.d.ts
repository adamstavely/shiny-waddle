import { K8sRBACTest } from '../core/types';
export declare class K8sRBACValidator {
    validateFiles(files: string[]): Promise<K8sRBACTest>;
    private validateRule;
    private parseYAML;
}
