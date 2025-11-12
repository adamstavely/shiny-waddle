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
  createdAt: Date;
  updatedAt: Date;
}

export interface TicketingConfig {
  // Common fields
  baseUrl: string;
  apiToken: string;
  projectKey?: string; // For Jira
  projectId?: string; // For ServiceNow
  repository?: string; // For GitHub (owner/repo)
  
  // Provider-specific
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
  externalId: string; // Ticket ID in external system
  externalUrl: string; // URL to ticket in external system
  title: string;
  description: string;
  status: TicketStatus;
  priority: string;
  assignee?: string;
  violationId: string; // Link to violation
  violationTitle: string;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
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

