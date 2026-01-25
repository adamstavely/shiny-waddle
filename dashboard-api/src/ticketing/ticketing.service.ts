import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { CreateTicketingIntegrationDto } from './dto/create-ticketing-integration.dto';
import {
  TicketingIntegration,
  TicketingProvider,
  Ticket,
  TicketStatus,
  CreateTicketDto,
} from './entities/ticketing.entity';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

@Injectable()
export class TicketingService {
  private readonly integrationsFile = path.join(process.cwd(), '..', 'data', 'ticketing-integrations.json');
  private readonly ticketsFile = path.join(process.cwd(), '..', 'data', 'tickets.json');
  private integrations: TicketingIntegration[] = [];
  private tickets: Ticket[] = [];

  constructor() {
    this.loadData().catch(err => {
      console.error('Error loading ticketing data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      // Load integrations
      try {
        const integrationsData = await fs.readFile(this.integrationsFile, 'utf-8');
        this.integrations = JSON.parse(integrationsData);
      } catch {
        this.integrations = [];
      }

      // Load tickets
      try {
        const ticketsData = await fs.readFile(this.ticketsFile, 'utf-8');
        this.tickets = JSON.parse(ticketsData);
      } catch {
        this.tickets = [];
      }
    } catch (error) {
      console.error('Error loading ticketing data:', error);
    }
  }

  private async saveIntegrations(): Promise<void> {
    try {
      const dir = path.dirname(this.integrationsFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.integrationsFile, JSON.stringify(this.integrations, null, 2));
    } catch (error) {
      console.error('Error saving integrations:', error);
      throw error;
    }
  }

  private async saveTickets(): Promise<void> {
    try {
      const dir = path.dirname(this.ticketsFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.ticketsFile, JSON.stringify(this.tickets, null, 2));
    } catch (error) {
      console.error('Error saving tickets:', error);
      throw error;
    }
  }

  // Integration Management
  async createIntegration(dto: CreateTicketingIntegrationDto): Promise<TicketingIntegration> {
    const integration: TicketingIntegration = {
      id: uuidv4(),
      provider: dto.provider,
      name: dto.name,
      enabled: dto.enabled,
      config: dto.config,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Test connection
    await this.testConnection(integration);

    this.integrations.push(integration);
    await this.saveIntegrations();

    return integration;
  }

  async findAllIntegrations(): Promise<TicketingIntegration[]> {
    return this.integrations;
  }

  async findOneIntegration(id: string): Promise<TicketingIntegration> {
    const integration = this.integrations.find(i => i.id === id);
    if (!integration) {
      throw new NotFoundException(`Integration with ID ${id} not found`);
    }
    return integration;
  }

  async updateIntegration(id: string, updates: Partial<TicketingIntegration>): Promise<TicketingIntegration> {
    const index = this.integrations.findIndex(i => i.id === id);
    if (index === -1) {
      throw new NotFoundException(`Integration with ID ${id} not found`);
    }

    this.integrations[index] = {
      ...this.integrations[index],
      ...updates,
      updatedAt: new Date(),
    };

    await this.saveIntegrations();
    return this.integrations[index];
  }

  async deleteIntegration(id: string): Promise<void> {
    const index = this.integrations.findIndex(i => i.id === id);
    if (index === -1) {
      throw new NotFoundException(`Integration with ID ${id} not found`);
    }

    this.integrations.splice(index, 1);
    await this.saveIntegrations();
  }

  async testConnection(integration: TicketingIntegration): Promise<boolean> {
    try {
      switch (integration.provider) {
        case TicketingProvider.JIRA:
          return await this.testJiraConnection(integration);
        case TicketingProvider.SERVICENOW:
          return await this.testServiceNowConnection(integration);
        case TicketingProvider.GITHUB:
          return await this.testGitHubConnection(integration);
        default:
          throw new BadRequestException(`Unsupported provider: ${integration.provider}`);
      }
    } catch (error) {
      console.error(`Connection test failed for ${integration.provider}:`, error);
      throw new BadRequestException(`Connection test failed: ${error.message}`);
    }
  }

  private async testJiraConnection(integration: TicketingIntegration): Promise<boolean> {
    const { baseUrl, jira } = integration.config;
    if (!jira) {
      throw new BadRequestException('Jira configuration missing');
    }

    const response = await axios.get(`${baseUrl}/rest/api/3/myself`, {
      auth: {
        username: jira.email,
        password: jira.apiToken,
      },
    });

    return response.status === 200;
  }

  private async testServiceNowConnection(integration: TicketingIntegration): Promise<boolean> {
    const { servicenow } = integration.config;
    if (!servicenow) {
      throw new BadRequestException('ServiceNow configuration missing');
    }

    const response = await axios.get(
      `https://${servicenow.instance}.service-now.com/api/now/table/sys_user`,
      {
        auth: {
          username: servicenow.username,
          password: servicenow.password,
        },
        params: {
          sysparm_limit: 1,
        },
      }
    );

    return response.status === 200;
  }

  private async testGitHubConnection(integration: TicketingIntegration): Promise<boolean> {
    const { github, apiToken } = integration.config;
    if (!github) {
      throw new BadRequestException('GitHub configuration missing');
    }

    const response = await axios.get(
      `https://api.github.com/repos/${github.owner}/${github.repo}`,
      {
        headers: {
          Authorization: `token ${apiToken}`,
        },
      }
    );

    return response.status === 200;
  }

  // Ticket Management
  async createTicket(integrationId: string, dto: CreateTicketDto): Promise<Ticket> {
    const integration = await this.findOneIntegration(integrationId);
    if (!integration.enabled) {
      throw new BadRequestException('Integration is not enabled');
    }

    let externalTicket: any;
    let externalId: string;
    let externalUrl: string;

    switch (integration.provider) {
      case TicketingProvider.JIRA:
        ({ externalTicket, externalId, externalUrl } = await this.createJiraTicket(integration, dto));
        break;
      case TicketingProvider.SERVICENOW:
        ({ externalTicket, externalId, externalUrl } = await this.createServiceNowTicket(integration, dto));
        break;
      case TicketingProvider.GITHUB:
        ({ externalTicket, externalId, externalUrl } = await this.createGitHubIssue(integration, dto));
        break;
      default:
        throw new BadRequestException(`Unsupported provider: ${integration.provider}`);
    }

    const ticket: Ticket = {
      id: uuidv4(),
      provider: integration.provider,
      externalId,
      externalUrl,
      title: dto.title,
      description: dto.description,
      status: TicketStatus.OPEN,
      priority: dto.priority || 'medium',
      assignee: dto.assignee,
      violationId: dto.violationId,
      violationTitle: dto.title,
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: externalTicket,
    };

    this.tickets.push(ticket);
    await this.saveTickets();

    return ticket;
  }

  private async createJiraTicket(integration: TicketingIntegration, dto: CreateTicketDto): Promise<any> {
    const { baseUrl, projectKey, jira } = integration.config;
    if (!jira || !projectKey) {
      throw new BadRequestException('Jira configuration incomplete');
    }

    const issueType = jira.issueType || 'Bug';
    const priority = jira.priorityMapping?.[dto.priority || 'medium'] || 'Medium';

    const response = await axios.post(
      `${baseUrl}/rest/api/3/issue`,
      {
        fields: {
          project: { key: projectKey },
          summary: dto.title,
          description: {
            type: 'doc',
            version: 1,
            content: [
              {
                type: 'paragraph',
                content: [
                  {
                    type: 'text',
                    text: dto.description,
                  },
                ],
              },
            ],
          },
          issuetype: { name: issueType },
          priority: { name: priority },
          ...(dto.assignee && { assignee: { accountId: dto.assignee } }),
        },
      },
      {
        auth: {
          username: jira.email,
          password: jira.apiToken,
        },
      }
    );

    return {
      externalTicket: response.data,
      externalId: response.data.key,
      externalUrl: `${baseUrl}/browse/${response.data.key}`,
    };
  }

  private async createServiceNowTicket(integration: TicketingIntegration, dto: CreateTicketDto): Promise<any> {
    const { servicenow } = integration.config;
    if (!servicenow) {
      throw new BadRequestException('ServiceNow configuration incomplete');
    }

    const tableName = servicenow.tableName || 'incident';

    const response = await axios.post(
      `https://${servicenow.instance}.service-now.com/api/now/table/${tableName}`,
      {
        short_description: dto.title,
        description: dto.description,
        priority: dto.priority || '3',
        ...(dto.assignee && { assigned_to: dto.assignee }),
      },
      {
        auth: {
          username: servicenow.username,
          password: servicenow.password,
        },
      }
    );

    return {
      externalTicket: response.data.result,
      externalId: response.data.result.sys_id,
      externalUrl: `https://${servicenow.instance}.service-now.com/nav_to.do?uri=/${tableName}.do?sys_id=${response.data.result.sys_id}`,
    };
  }

  private async createGitHubIssue(integration: TicketingIntegration, dto: CreateTicketDto): Promise<any> {
    const { github, apiToken } = integration.config;
    if (!github) {
      throw new BadRequestException('GitHub configuration incomplete');
    }

    const labels = [...(github.labels || []), ...(dto.labels || [])];

    const response = await axios.post(
      `https://api.github.com/repos/${github.owner}/${github.repo}/issues`,
      {
        title: dto.title,
        body: dto.description,
        labels,
        ...(dto.assignee && { assignees: [dto.assignee] }),
      },
      {
        headers: {
          Authorization: `token ${apiToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      }
    );

    return {
      externalTicket: response.data,
      externalId: response.data.number.toString(),
      externalUrl: response.data.html_url,
    };
  }

  async findAllTickets(violationId?: string): Promise<Ticket[]> {
    if (violationId) {
      return this.tickets.filter(t => t.violationId === violationId);
    }
    return this.tickets;
  }

  async findOneTicket(id: string): Promise<Ticket> {
    const ticket = this.tickets.find(t => t.id === id);
    if (!ticket) {
      throw new NotFoundException(`Ticket with ID ${id} not found`);
    }
    return ticket;
  }

  async syncTicketStatus(ticketId: string): Promise<Ticket> {
    const ticket = await this.findOneTicket(ticketId);
    const integration = await this.findOneIntegration(
      this.integrations.find(i => i.provider === ticket.provider)?.id || ''
    );

    // Sync status from external system
    // This would fetch the current status from Jira/ServiceNow/GitHub
    // For now, return the ticket as-is

    return ticket;
  }
}

