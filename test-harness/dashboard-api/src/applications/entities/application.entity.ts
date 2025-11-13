import { ApplicationType, ApplicationStatus } from '../dto/create-application.dto';

export interface TestConfigurationOverride {
  enabled: boolean;
  reason?: string;
  updatedBy?: string;
  updatedAt?: Date;
}

export interface ValidatorOverride {
  enabled: boolean;
  reason?: string;
  updatedBy?: string;
  updatedAt?: Date;
}

export interface Application {
  id: string;
  name: string;
  type: ApplicationType;
  status: ApplicationStatus;
  baseUrl?: string;
  team?: string;
  description?: string;
  config?: Record<string, any>;
  testConfigurationIds?: string[];
  testConfigurationOverrides?: {
    [configId: string]: TestConfigurationOverride;
  };
  validatorOverrides?: {
    [validatorId: string]: ValidatorOverride;
  };
  registeredAt: Date;
  lastTestAt?: Date;
  updatedAt: Date;
}

