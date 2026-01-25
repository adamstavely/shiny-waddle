export enum TicketingProvider {
  JIRA = 'jira',
  SERVICENOW = 'servicenow',
  GITHUB = 'github',
}

export enum TicketStatus {
  OPEN = 'open',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  CLOSED = 'closed',
}

export interface TicketingIntegration {
  id: string;
  provider: TicketingProvider;
  name: string;
  enabled: boolean;
  config: TicketingConfig;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface TicketingConfig {
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
}

export interface Ticket {
  id: string;
  provider: TicketingProvider;
  externalId: string;
  externalUrl: string;
  title: string;
  description: string;
  status: TicketStatus;
  priority: string;
  assignee?: string;
  violationId: string;
  violationTitle: string;
  createdAt: Date | string;
  updatedAt: Date | string;
  resolvedAt?: Date | string;
  metadata?: Record<string, any>;
}

export interface CreateTicketDto {
  violationId: string;
  title: string;
  description: string;
  priority?: string;
  assignee?: string;
  labels?: string[];
}

