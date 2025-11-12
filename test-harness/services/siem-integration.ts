/**
 * SIEM Integration Service
 * 
 * Provides integration with SIEM systems (Splunk, QRadar, Sentinel, custom)
 */

import { UnifiedFinding } from '../core/unified-finding-schema';
import axios, { AxiosInstance } from 'axios';

export interface SIEMConfig {
  type: 'splunk' | 'qradar' | 'sentinel' | 'custom';
  enabled: boolean;
  endpoint: string;
  authentication: {
    type: 'basic' | 'bearer' | 'api-key' | 'oauth2';
    credentials: Record<string, string>;
  };
  options?: Record<string, any>;
}

export interface SIEMEvent {
  timestamp: string;
  source: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  raw: any;
}

export interface SIEMQueryResult {
  events: SIEMEvent[];
  total: number;
  query: string;
}

export abstract class BaseSIEMAdapter {
  protected config: SIEMConfig;
  protected client: AxiosInstance;

  constructor(config: SIEMConfig) {
    this.config = config;
    this.client = axios.create({
      baseURL: config.endpoint,
      timeout: 30000,
    });

    // Setup authentication
    this.setupAuthentication();
  }

  protected setupAuthentication(): void {
    const { authentication } = this.config;
    
    switch (authentication.type) {
      case 'basic':
        this.client.defaults.auth = {
          username: authentication.credentials.username || '',
          password: authentication.credentials.password || '',
        };
        break;
      case 'bearer':
        this.client.defaults.headers.common['Authorization'] = 
          `Bearer ${authentication.credentials.token}`;
        break;
      case 'api-key':
        const apiKeyHeader = authentication.credentials.headerName || 'X-API-Key';
        this.client.defaults.headers.common[apiKeyHeader] = 
          authentication.credentials.apiKey || '';
        break;
      case 'oauth2':
        // OAuth2 handled separately
        break;
    }
  }

  abstract sendFinding(finding: UnifiedFinding): Promise<boolean>;
  abstract queryEvents(query: string, timeRange?: { start: Date; end: Date }): Promise<SIEMQueryResult>;
  abstract testConnection(): Promise<boolean>;
}

/**
 * Splunk SIEM Adapter
 */
export class SplunkAdapter extends BaseSIEMAdapter {
  private sessionKey?: string;

  async testConnection(): Promise<boolean> {
    try {
      const response = await this.client.get('/services/auth/login', {
        params: {
          username: this.config.authentication.credentials.username,
          password: this.config.authentication.credentials.password,
        },
      });

      // Extract session key from response
      const sessionKeyMatch = response.data.match(/<sessionKey>([^<]+)<\/sessionKey>/);
      if (sessionKeyMatch) {
        this.sessionKey = sessionKeyMatch[1];
        this.client.defaults.headers.common['Authorization'] = `Splunk ${this.sessionKey}`;
      }

      return response.status === 200;
    } catch (error: any) {
      console.error('Splunk connection test failed:', error.message);
      return false;
    }
  }

  async sendFinding(finding: UnifiedFinding): Promise<boolean> {
    try {
      if (!this.sessionKey) {
        await this.testConnection();
      }

      const event = this.convertFindingToSplunkEvent(finding);
      const index = this.config.options?.index || 'security';

      const response = await this.client.post(
        `/services/receivers/simple`,
        `event=${encodeURIComponent(JSON.stringify(event))}`,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          params: {
            sourcetype: 'aspm:security:findings',
            index,
          },
        }
      );

      return response.status === 200;
    } catch (error: any) {
      console.error('Failed to send finding to Splunk:', error.message);
      return false;
    }
  }

  async queryEvents(query: string, timeRange?: { start: Date; end: Date }): Promise<SIEMQueryResult> {
    try {
      if (!this.sessionKey) {
        await this.testConnection();
      }

      const searchQuery = this.buildSplunkQuery(query, timeRange);
      const searchResponse = await this.client.post(
        '/services/search/jobs',
        {
          search: searchQuery,
          output_mode: 'json',
        }
      );

      const jobId = searchResponse.data.sid;
      
      // Poll for results
      let results: any = null;
      let attempts = 0;
      while (attempts < 30) {
        const statusResponse = await this.client.get(`/services/search/jobs/${jobId}`, {
          params: { output_mode: 'json' },
        });

        if (statusResponse.data.entry[0].content.isDone) {
          const resultsResponse = await this.client.get(`/services/search/jobs/${jobId}/results`, {
            params: { output_mode: 'json' },
          });
          results = resultsResponse.data;
          break;
        }

        await new Promise(resolve => setTimeout(resolve, 1000));
        attempts++;
      }

      if (!results) {
        throw new Error('Search job did not complete in time');
      }

      const events = results.results.map((r: any) => this.parseSplunkEvent(r));
      
      return {
        events,
        total: results.total || events.length,
        query: searchQuery,
      };
    } catch (error: any) {
      console.error('Splunk query failed:', error.message);
      throw error;
    }
  }

  private convertFindingToSplunkEvent(finding: UnifiedFinding): any {
    return {
      time: finding.createdAt ? new Date(finding.createdAt).getTime() / 1000 : Date.now() / 1000,
      event: {
        finding_id: finding.id,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        source: finding.source,
        scanner_id: finding.scannerId,
        risk_score: finding.riskScore,
        status: finding.status,
        asset_type: finding.asset?.type,
        asset_component: finding.asset?.component,
        compliance_frameworks: finding.compliance?.frameworks || [],
        vulnerability_cve: finding.vulnerability?.cveId,
        vulnerability_cwe: finding.vulnerability?.cweId,
        raw: finding.raw,
      },
    };
  }

  private buildSplunkQuery(query: string, timeRange?: { start: Date; end: Date }): string {
    let splunkQuery = `index=${this.config.options?.index || 'security'} sourcetype=aspm:security:findings`;
    
    if (timeRange) {
      const startTime = Math.floor(timeRange.start.getTime() / 1000);
      const endTime = Math.floor(timeRange.end.getTime() / 1000);
      splunkQuery += ` earliest=${startTime} latest=${endTime}`;
    }

    if (query) {
      splunkQuery += ` | ${query}`;
    }

    return splunkQuery;
  }

  private parseSplunkEvent(result: any): SIEMEvent {
    const event = result.event || result;
    return {
      timestamp: new Date(event.time * 1000).toISOString(),
      source: 'splunk',
      severity: event.severity || 'medium',
      category: event.source || 'security',
      title: event.title || 'Unknown Event',
      description: event.description || '',
      raw: event,
    };
  }
}

/**
 * QRadar SIEM Adapter
 */
export class QRadarAdapter extends BaseSIEMAdapter {
  async testConnection(): Promise<boolean> {
    try {
      const response = await this.client.get('/api/help/resources');
      return response.status === 200;
    } catch (error: any) {
      console.error('QRadar connection test failed:', error.message);
      return false;
    }
  }

  async sendFinding(finding: UnifiedFinding): Promise<boolean> {
    try {
      const event = this.convertFindingToQRadarEvent(finding);
      
      const response = await this.client.post('/api/siem/events', event, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      return response.status === 200 || response.status === 201;
    } catch (error: any) {
      console.error('Failed to send finding to QRadar:', error.message);
      return false;
    }
  }

  async queryEvents(query: string, timeRange?: { start: Date; end: Date }): Promise<SIEMQueryResult> {
    try {
      const aqlQuery = this.buildQRadarQuery(query, timeRange);
      
      const response = await this.client.post(
        '/api/ariel/searches',
        {
          query_expression: aqlQuery,
        },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      const searchId = response.data.search_id;
      
      // Poll for results
      let results: any = null;
      let attempts = 0;
      while (attempts < 30) {
        const statusResponse = await this.client.get(`/api/ariel/searches/${searchId}`);
        
        if (statusResponse.data.status === 'COMPLETED') {
          const resultsResponse = await this.client.get(`/api/ariel/searches/${searchId}/results`);
          results = resultsResponse.data;
          break;
        }

        await new Promise(resolve => setTimeout(resolve, 1000));
        attempts++;
      }

      if (!results) {
        throw new Error('Search did not complete in time');
      }

      const events = results.events.map((e: any) => this.parseQRadarEvent(e));
      
      return {
        events,
        total: results.events.length,
        query: aqlQuery,
      };
    } catch (error: any) {
      console.error('QRadar query failed:', error.message);
      throw error;
    }
  }

  private convertFindingToQRadarEvent(finding: UnifiedFinding): any {
    const severityMap: Record<string, number> = {
      critical: 10,
      high: 8,
      medium: 5,
      low: 3,
      info: 1,
    };

    return {
      qid: this.config.options?.qid || 1000001,
      category: 1000,
      severity: severityMap[finding.severity] || 5,
      magnitude: finding.riskScore || 0,
      sourceIP: finding.asset?.location?.endpoint || '0.0.0.0',
      destinationIP: '0.0.0.0',
      username: finding.assignedTo || 'system',
      logSourceId: this.config.options?.logSourceId || 1,
      startTime: finding.createdAt ? new Date(finding.createdAt).getTime() : Date.now(),
      payload: JSON.stringify({
        finding_id: finding.id,
        title: finding.title,
        description: finding.description,
        source: finding.source,
        scanner_id: finding.scannerId,
        compliance_frameworks: finding.compliance?.frameworks || [],
      }),
    };
  }

  private buildQRadarQuery(query: string, timeRange?: { start: Date; end: Date }): string {
    let aqlQuery = 'SELECT * FROM events';
    
    if (timeRange) {
      const startTime = timeRange.start.getTime();
      const endTime = timeRange.end.getTime();
      aqlQuery += ` WHERE startTime >= ${startTime} AND startTime <= ${endTime}`;
    }

    if (query) {
      aqlQuery += ` AND ${query}`;
    }

    return aqlQuery;
  }

  private parseQRadarEvent(event: any): SIEMEvent {
    let payload: any = {};
    try {
      payload = typeof event.payload === 'string' ? JSON.parse(event.payload) : event.payload;
    } catch {
      payload = {};
    }

    return {
      timestamp: new Date(event.startTime).toISOString(),
      source: 'qradar',
      severity: this.mapQRadarSeverity(event.severity),
      category: 'security',
      title: payload.title || 'QRadar Event',
      description: payload.description || '',
      raw: event,
    };
  }

  private mapQRadarSeverity(severity: number): string {
    if (severity >= 8) return 'high';
    if (severity >= 5) return 'medium';
    if (severity >= 3) return 'low';
    return 'info';
  }
}

/**
 * Azure Sentinel SIEM Adapter
 */
export class SentinelAdapter extends BaseSIEMAdapter {
  private accessToken?: string;

  async testConnection(): Promise<boolean> {
    try {
      await this.authenticate();
      const response = await this.client.get('/api/loganalytics/v1/workspaces');
      return response.status === 200;
    } catch (error: any) {
      console.error('Sentinel connection test failed:', error.message);
      return false;
    }
  }

  private async authenticate(): Promise<void> {
    if (this.accessToken) return;

    const { credentials } = this.config.authentication;
    const tenantId = credentials.tenantId;
    const clientId = credentials.clientId;
    const clientSecret = credentials.clientSecret;

    const tokenResponse = await axios.post(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        scope: 'https://api.loganalytics.io/.default',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    this.accessToken = tokenResponse.data.access_token;
    this.client.defaults.headers.common['Authorization'] = `Bearer ${this.accessToken}`;
  }

  async sendFinding(finding: UnifiedFinding): Promise<boolean> {
    try {
      await this.authenticate();

      const workspaceId = this.config.options?.workspaceId;
      if (!workspaceId) {
        throw new Error('Workspace ID is required for Sentinel');
      }

      const event = this.convertFindingToSentinelEvent(finding);
      
      const response = await this.client.post(
        `/api/loganalytics/v1/workspaces/${workspaceId}/tables/ASPMFindings_CL/rows`,
        [event],
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      return response.status === 200 || response.status === 201;
    } catch (error: any) {
      console.error('Failed to send finding to Sentinel:', error.message);
      return false;
    }
  }

  async queryEvents(query: string, timeRange?: { start: Date; end: Date }): Promise<SIEMQueryResult> {
    try {
      await this.authenticate();

      const workspaceId = this.config.options?.workspaceId;
      if (!workspaceId) {
        throw new Error('Workspace ID is required for Sentinel');
      }

      const kqlQuery = this.buildSentinelQuery(query, timeRange);
      
      const response = await this.client.post(
        `/api/loganalytics/v1/workspaces/${workspaceId}/query`,
        {
          query: kqlQuery,
        },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      const events = (response.data.tables[0]?.rows || []).map((row: any[]) => 
        this.parseSentinelEvent(row, response.data.tables[0]?.columns || [])
      );
      
      return {
        events,
        total: events.length,
        query: kqlQuery,
      };
    } catch (error: any) {
      console.error('Sentinel query failed:', error.message);
      throw error;
    }
  }

  private convertFindingToSentinelEvent(finding: UnifiedFinding): any {
    return {
      TimeGenerated: finding.createdAt || new Date().toISOString(),
      FindingId: finding.id,
      Title: finding.title,
      Description: finding.description,
      Severity: finding.severity,
      Source: finding.source,
      ScannerId: finding.scannerId,
      RiskScore: finding.riskScore,
      Status: finding.status,
      AssetType: finding.asset?.type,
      AssetComponent: finding.asset?.component,
      ComplianceFrameworks: finding.compliance?.frameworks || [],
      VulnerabilityCVE: finding.vulnerability?.cveId,
      VulnerabilityCWE: finding.vulnerability?.cweId,
    };
  }

  private buildSentinelQuery(query: string, timeRange?: { start: Date; end: Date }): string {
    let kqlQuery = 'ASPMFindings_CL';
    
    if (timeRange) {
      const startTime = timeRange.start.toISOString();
      const endTime = timeRange.end.toISOString();
      kqlQuery += ` | where TimeGenerated between (datetime(${startTime}) .. datetime(${endTime}))`;
    }

    if (query) {
      kqlQuery += ` | ${query}`;
    }

    return kqlQuery;
  }

  private parseSentinelEvent(row: any[], columns: any[]): SIEMEvent {
    const event: any = {};
    columns.forEach((col: any, index: number) => {
      event[col.name] = row[index];
    });

    return {
      timestamp: event.TimeGenerated || new Date().toISOString(),
      source: 'sentinel',
      severity: event.Severity || 'medium',
      category: 'security',
      title: event.Title || 'Sentinel Event',
      description: event.Description || '',
      raw: event,
    };
  }
}

/**
 * SIEM Integration Service
 */
export class SIEMIntegration {
  private adapters: Map<string, BaseSIEMAdapter> = new Map();

  /**
   * Register a SIEM adapter
   */
  registerAdapter(id: string, adapter: BaseSIEMAdapter): void {
    this.adapters.set(id, adapter);
  }

  /**
   * Create adapter from config
   */
  createAdapter(config: SIEMConfig): BaseSIEMAdapter {
    switch (config.type) {
      case 'splunk':
        return new SplunkAdapter(config);
      case 'qradar':
        return new QRadarAdapter(config);
      case 'sentinel':
        return new SentinelAdapter(config);
      default:
        throw new Error(`Unsupported SIEM type: ${config.type}`);
    }
  }

  /**
   * Send finding to all enabled SIEM systems
   */
  async sendFindingToAll(finding: UnifiedFinding): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();

    for (const [id, adapter] of this.adapters.entries()) {
      if (adapter['config'].enabled) {
        try {
          const success = await adapter.sendFinding(finding);
          results.set(id, success);
        } catch (error: any) {
          console.error(`Failed to send finding to ${id}:`, error.message);
          results.set(id, false);
        }
      }
    }

    return results;
  }

  /**
   * Query events from a specific SIEM
   */
  async querySIEM(
    siemId: string,
    query: string,
    timeRange?: { start: Date; end: Date }
  ): Promise<SIEMQueryResult> {
    const adapter = this.adapters.get(siemId);
    if (!adapter) {
      throw new Error(`SIEM adapter ${siemId} not found`);
    }

    return await adapter.queryEvents(query, timeRange);
  }

  /**
   * Test connection to a SIEM
   */
  async testSIEMConnection(siemId: string): Promise<boolean> {
    const adapter = this.adapters.get(siemId);
    if (!adapter) {
      throw new Error(`SIEM adapter ${siemId} not found`);
    }

    return await adapter.testConnection();
  }
}

