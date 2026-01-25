import { TicketingProvider } from '../entities/ticketing.entity';

export interface CreateTicketingIntegrationDto {
  provider: TicketingProvider;
  name: string;
  enabled: boolean;
  config: {
    baseUrl: string;
    apiToken: string;
    projectKey?: string;
    projectId?: string;
    repository?: string;
    jira?: {
      email: string;
      apiToken: string;
      issueType?: string;
      priorityMapping?: Record<string, string>;
    };
    servicenow?: {
      instance: string;
      username: string;
      password: string;
      tableName?: string;
    };
    github?: {
      owner: string;
      repo: string;
      labels?: string[];
    };
  };
}

