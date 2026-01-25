import { IACScanResult } from '../core/types';
export declare class IACScanner {
    scanTerraform(files: string[]): Promise<IACScanResult>;
    scanCloudFormation(templates: string[]): Promise<IACScanResult>;
    scanFiles(files: string[]): Promise<IACScanResult>;
    validateAccessControl(iacConfig: any): Promise<any[]>;
    private detectHardcodedSecret;
    private detectOverlyPermissive;
    private detectMissingPolicy;
}
