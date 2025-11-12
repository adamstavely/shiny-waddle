import { ZTAPillar, ZTAAssessment, ComplianceAssessment } from '../core/types';
export interface NIST800207Config {
    controlStatuses?: {
        identity?: Array<{
            id: string;
            name: string;
            description: string;
            status: 'compliant' | 'non-compliant' | 'partial';
            evidence: string[];
        }>;
        device?: Array<{
            id: string;
            name: string;
            description: string;
            status: 'compliant' | 'non-compliant' | 'partial';
            evidence: string[];
        }>;
        network?: Array<{
            id: string;
            name: string;
            description: string;
            status: 'compliant' | 'non-compliant' | 'partial';
            evidence: string[];
        }>;
        application?: Array<{
            id: string;
            name: string;
            description: string;
            status: 'compliant' | 'non-compliant' | 'partial';
            evidence: string[];
        }>;
        data?: Array<{
            id: string;
            name: string;
            description: string;
            status: 'compliant' | 'non-compliant' | 'partial';
            evidence: string[];
        }>;
    };
    complianceThreshold?: number;
    assessmentProvider?: {
        assessIdentityPillar(): Promise<ZTAPillar>;
        assessDevicePillar(): Promise<ZTAPillar>;
        assessNetworkPillar(): Promise<ZTAPillar>;
        assessApplicationPillar(): Promise<ZTAPillar>;
        assessDataPillar(): Promise<ZTAPillar>;
    };
}
export declare class NIST800207Compliance {
    private config;
    constructor(config?: NIST800207Config);
    assessZTAPillars(assessment: Partial<ZTAAssessment>): Promise<ComplianceAssessment>;
    testIdentityPillar(config: any): Promise<ZTAPillar>;
    testDevicePillar(config: any): Promise<ZTAPillar>;
    testNetworkPillar(config: any): Promise<ZTAPillar>;
    testApplicationPillar(config: any): Promise<ZTAPillar>;
    testDataPillar(config: any): Promise<ZTAPillar>;
    generateComplianceReport(assessment: ComplianceAssessment): Promise<string>;
}
