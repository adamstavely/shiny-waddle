export enum SalesforceExperienceCloudTestType {
  GUEST_ACCESS = 'guest-access',
  AUTHENTICATED_ACCESS = 'authenticated-access',
  GRAPHQL = 'graphql',
  SELF_REGISTRATION = 'self-registration',
  RECORD_LISTS = 'record-lists',
  HOME_URLS = 'home-urls',
  OBJECT_ACCESS = 'object-access',
  FULL_AUDIT = 'full-audit',
}

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

export interface SalesforceExperienceCloudTestResultEntity {
  id: string;
  configId: string;
  testName: string;
  testType: SalesforceExperienceCloudTestType;
  status: 'passed' | 'failed' | 'warning';
  findings?: Array<{
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;
    details: any;
    objects?: string[];
    urls?: string[];
    recordCount?: number;
    accessibleRecords?: any[];
  }>;
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
