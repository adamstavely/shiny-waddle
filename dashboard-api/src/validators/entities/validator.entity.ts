import { ValidatorStatus } from '../dto/create-validator.dto';

export interface ValidatorEntity {
  id: string;
  name: string;
  description: string;
  testType: string;
  version: string;
  metadata?: {
    supportedTestTypes?: string[];
    requiredConfig?: string[];
    optionalConfig?: string[];
    dependencies?: string[];
    tags?: string[];
    exampleConfig?: any;
  };
  config?: Record<string, any>;
  enabled: boolean;
  registeredAt: Date;
  lastRunAt?: Date;
  testCount: number;
  successCount: number;
  failureCount: number;
  updatedAt: Date;
}

