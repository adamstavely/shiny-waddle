import { ApplicationType, ApplicationStatus } from '../dto/create-application.dto';

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
  registeredAt: Date;
  lastTestAt?: Date;
  updatedAt: Date;
}

