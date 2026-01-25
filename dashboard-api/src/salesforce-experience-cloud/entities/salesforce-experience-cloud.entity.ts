import { SalesforceExperienceCloudTestType } from '../../../../dashboard-frontend/src/types/salesforce-experience-cloud';

export interface SalesforceExperienceCloudConfigEntity {
  id: string;
  name: string;
  url: string;
  cookies?: string;
  outputDir?: string;
  objectList?: string[];
  app?: string;
  aura?: string;
  context?: string;
  token?: string;
  noGraphQL?: boolean;
  proxy?: string;
  insecure?: boolean;
  auraRequestFile?: string;
  auraInspectorPath?: string;
  timeout?: number;
  pythonPath?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuraInspectorFinding {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  details: any;
  objects?: string[];
  urls?: string[];
  recordCount?: number;
  accessibleRecords?: any[];
}

export interface SalesforceExperienceCloudTestResultEntity {
  id: string;
  configId: string;
  testName: string;
  testType: SalesforceExperienceCloudTestType | string;
  status: 'passed' | 'failed' | 'warning';
  findings?: AuraInspectorFinding[];
  accessibleRecords?: any[];
  recordCount?: number;
  urls?: string[];
  objects?: string[];
  summary?: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount?: number;
    infoCount?: number;
  };
  details?: Record<string, any>;
  error?: string;
  timestamp: Date;
  createdAt: Date;
}
