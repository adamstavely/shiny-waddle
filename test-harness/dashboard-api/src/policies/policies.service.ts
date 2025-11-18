import { Injectable, NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { CreatePolicyDto, PolicyType, PolicyStatus, PolicyEffect } from './dto/create-policy.dto';
import { UpdatePolicyDto } from './dto/update-policy.dto';
import { Policy, PolicyVersion, PolicyAuditLog } from './entities/policy.entity';
import { PolicyVersioningService, VersionComparison, ImpactAnalysis } from './services/policy-versioning.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class PoliciesService {
  private readonly policiesFile = path.join(process.cwd(), '..', '..', 'data', 'policies.json');
  private readonly auditLogFile = path.join(process.cwd(), '..', '..', 'data', 'policy-audit.json');
  private readonly domainConfigsFile = path.join(process.cwd(), '..', '..', 'data', 'domain-configs.json');
  private policies: Policy[] = [];
  private auditLogs: PolicyAuditLog[] = [];
  private domainConfigs: Record<string, any> = {};

  constructor(
    private readonly moduleRef: ModuleRef,
    private readonly versioningService: PolicyVersioningService,
  ) {
    this.loadPolicies().catch(err => {
      console.error('Error loading policies on startup:', err);
    });
    this.loadAuditLogs().catch(err => {
      console.error('Error loading audit logs on startup:', err);
    });
    this.loadDomainConfigs().catch(err => {
      console.error('Error loading domain configs on startup:', err);
    });
  }

  private async loadPolicies(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.policiesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.policiesFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.policies = (Array.isArray(parsed) ? parsed : []).map((policy: any) => ({
          ...policy,
          createdAt: new Date(policy.createdAt),
          updatedAt: new Date(policy.updatedAt),
          lastDeployedAt: policy.lastDeployedAt ? new Date(policy.lastDeployedAt) : undefined,
          versions: (policy.versions || []).map((v: any) => ({
            ...v,
            date: new Date(v.date),
          })),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.policies = [];
          await this.savePolicies();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading policies:', error);
      this.policies = [];
    }
  }

  private async savePolicies() {
    try {
      await fs.mkdir(path.dirname(this.policiesFile), { recursive: true });
      await fs.writeFile(this.policiesFile, JSON.stringify(this.policies, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving policies:', error);
      throw error;
    }
  }

  private async loadAuditLogs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.auditLogFile), { recursive: true });
      try {
        const data = await fs.readFile(this.auditLogFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.auditLogs = (Array.isArray(parsed) ? parsed : []).map((log: any) => ({
          ...log,
          timestamp: new Date(log.timestamp),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.auditLogs = [];
          await this.saveAuditLogs();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading audit logs:', error);
      this.auditLogs = [];
    }
  }

  private async saveAuditLogs() {
    try {
      await fs.mkdir(path.dirname(this.auditLogFile), { recursive: true });
      await fs.writeFile(this.auditLogFile, JSON.stringify(this.auditLogs, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving audit logs:', error);
      throw error;
    }
  }

  private async addAuditLog(
    policyId: string,
    action: PolicyAuditLog['action'],
    details?: Record<string, any>,
  ): Promise<void> {
    const log: PolicyAuditLog = {
      id: uuidv4(),
      policyId,
      action,
      timestamp: new Date(),
      details,
    };
    this.auditLogs.push(log);
    await this.saveAuditLogs();
  }

  async create(createPolicyDto: CreatePolicyDto): Promise<Policy> {
    const policy: Policy = {
      id: uuidv4(),
      name: createPolicyDto.name,
      description: createPolicyDto.description,
      type: createPolicyDto.type,
      version: createPolicyDto.version,
      status: createPolicyDto.status || PolicyStatus.DRAFT,
      effect: createPolicyDto.effect,
      priority: createPolicyDto.priority || 100,
      rules: createPolicyDto.rules || [],
      conditions: createPolicyDto.conditions || [],
      applicationId: createPolicyDto.applicationId,
      versions: [
        {
          version: createPolicyDto.version,
          status: createPolicyDto.status || PolicyStatus.DRAFT,
          date: new Date(),
          changes: [{ type: 'added', description: 'Initial policy creation' }],
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
      ruleCount: createPolicyDto.type === PolicyType.RBAC 
        ? (createPolicyDto.rules?.length || 0)
        : (createPolicyDto.conditions?.length || 0),
    };

    this.policies.push(policy);
    await this.savePolicies();
    await this.addAuditLog(policy.id, 'created', { version: policy.version });

    return policy;
  }

  async findAll(type?: PolicyType, status?: PolicyStatus, applicationId?: string): Promise<Policy[]> {
    let filtered = this.policies;

    if (type) {
      filtered = filtered.filter(p => p.type === type);
    }
    if (status) {
      filtered = filtered.filter(p => p.status === status);
    }
    if (applicationId) {
      filtered = filtered.filter(p => p.applicationId === applicationId);
    }

    return filtered;
  }

  async findOne(id: string): Promise<Policy> {
    const policy = this.policies.find(p => p.id === id);
    if (!policy) {
      throw new NotFoundException(`Policy with ID "${id}" not found`);
    }
    return policy;
  }

  async update(id: string, updatePolicyDto: UpdatePolicyDto): Promise<Policy> {
    const index = this.policies.findIndex(p => p.id === id);
    if (index === -1) {
      throw new NotFoundException(`Policy with ID "${id}" not found`);
    }

    const previousVersion = this.policies[index].version;
    const previousStatus = this.policies[index].status;

    this.policies[index] = {
      ...this.policies[index],
      ...updatePolicyDto,
      updatedAt: new Date(),
      ruleCount: updatePolicyDto.type === PolicyType.RBAC
        ? (updatePolicyDto.rules?.length || this.policies[index].rules?.length || 0)
        : (updatePolicyDto.conditions?.length || this.policies[index].conditions?.length || 0),
    };

    // Track status changes
    if (updatePolicyDto.status && updatePolicyDto.status !== previousStatus) {
      await this.addAuditLog(id, 'status_changed', {
        previousStatus,
        newStatus: updatePolicyDto.status,
      });
    }

    await this.savePolicies();
    await this.addAuditLog(id, 'updated', {
      previousVersion,
      newVersion: this.policies[index].version,
    });

    return this.policies[index];
  }

  async remove(id: string): Promise<void> {
    const index = this.policies.findIndex(p => p.id === id);
    if (index === -1) {
      throw new NotFoundException(`Policy with ID "${id}" not found`);
    }

    this.policies.splice(index, 1);
    await this.savePolicies();
    await this.addAuditLog(id, 'deleted');
  }

  async addVersion(id: string, version: PolicyVersion): Promise<Policy> {
    const policy = await this.findOne(id);
    policy.versions.unshift(version);
    policy.version = version.version;
    policy.status = version.status;
    policy.updatedAt = new Date();

    await this.savePolicies();
    await this.addAuditLog(id, 'updated', {
      newVersion: version.version,
      changes: version.changes,
    });

    return policy;
  }

  async getVersions(id: string): Promise<PolicyVersion[]> {
    const policy = await this.findOne(id);
    return this.versioningService.getVersionHistory(policy);
  }

  async compareVersions(id: string, version1: string, version2: string): Promise<VersionComparison> {
    const policy = await this.findOne(id);
    return this.versioningService.compareVersions(policy, version1, version2);
  }

  async analyzeImpact(id: string, version?: string): Promise<ImpactAnalysis> {
    const policy = await this.findOne(id);
    const targetVersion = version 
      ? this.versioningService.getVersion(policy, version)
      : policy.versions[0];
    
    if (!targetVersion) {
      throw new NotFoundException(`Version ${version || 'latest'} not found`);
    }

    return this.versioningService.analyzeImpact(policy, targetVersion);
  }

  private calculateDifferences(v1: PolicyVersion, v2: PolicyVersion): any {
    const differences: any = {};
    
    if (v1.status !== v2.status) {
      differences.status = { from: v1.status, to: v2.status };
    }
    
    if (v1.changes.length !== v2.changes.length) {
      differences.changes = {
        count: { from: v1.changes.length, to: v2.changes.length },
      };
    }

    return differences;
  }

  async deploy(id: string, version?: string): Promise<Policy> {
    const policy = await this.findOne(id);
    
    const deployVersion = version || policy.version;
    const versionData = policy.versions.find(v => v.version === deployVersion);
    
    if (!versionData) {
      throw new NotFoundException(`Version "${deployVersion}" not found`);
    }

    if (versionData.status !== PolicyStatus.ACTIVE) {
      throw new BadRequestException(`Cannot deploy version with status "${versionData.status}"`);
    }

    policy.lastDeployedAt = new Date();
    policy.deployedVersion = deployVersion;
    policy.status = PolicyStatus.ACTIVE;

    await this.savePolicies();
    await this.addAuditLog(id, 'deployed', { version: deployVersion });

    return policy;
  }

  async rollback(id: string, targetVersion: string): Promise<Policy> {
    const policy = await this.findOne(id);
    const rollbackResult = this.versioningService.rollbackToVersion(policy, targetVersion);

    const rollbackVersion: PolicyVersion = {
      version: rollbackResult.newVersion,
      status: policy.status,
      date: new Date(),
      changes: [
        {
          type: 'fixed',
          description: `Rollback to version ${targetVersion}`,
        },
      ],
      notes: rollbackResult.message,
    };

    policy.versions.unshift(rollbackVersion);
    policy.version = rollbackVersion.version;
    policy.updatedAt = new Date();

    await this.savePolicies();
    await this.addAuditLog(id, 'rolled_back', {
      from: policy.version,
      to: targetVersion,
      newVersion: rollbackResult.newVersion,
    });

    return policy;
  }

  async getAuditLogs(policyId: string): Promise<PolicyAuditLog[]> {
    return this.auditLogs
      .filter(log => log.policyId === policyId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async testPolicy(id: string, testData: any): Promise<any> {
    const policy = await this.findOne(id);
    
    // In a real implementation, this would execute the policy against test data
    // For now, return a mock result
    return {
      policyId: id,
      testData,
      result: 'passed',
      decisions: [],
      timestamp: new Date(),
    };
  }

  async findTestsUsingPolicy(policyId: string): Promise<any[]> {
    try {
      // Use ModuleRef to get TestsService (avoiding circular dependency)
      // Import dynamically to avoid circular dependency at module level
      const { TestsService } = await import('../tests/tests.service');
      const testsService = this.moduleRef.get(TestsService, { strict: false });
      if (testsService && typeof testsService.findByPolicy === 'function') {
        return await testsService.findByPolicy(policyId);
      }
      return [];
    } catch (error) {
      // TestsService may not be available, return empty array
      return [];
    }
  }

  // Domain-specific configuration methods
  private async loadDomainConfigs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.domainConfigsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.domainConfigsFile, 'utf-8');
        this.domainConfigs = JSON.parse(data);
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.domainConfigs = {};
          await this.saveDomainConfigs();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading domain configs:', error);
      this.domainConfigs = {};
    }
  }

  private async saveDomainConfigs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.domainConfigsFile), { recursive: true });
      await fs.writeFile(this.domainConfigsFile, JSON.stringify(this.domainConfigs, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving domain configs:', error);
      throw error;
    }
  }

  async getDomainConfig(domain: string): Promise<any> {
    await this.loadDomainConfigs();
    return this.domainConfigs[domain] || null;
  }

  async saveDomainConfig(domain: string, config: any): Promise<void> {
    await this.loadDomainConfigs();
    this.domainConfigs[domain] = {
      ...config,
      updatedAt: new Date().toISOString(),
    };
    await this.saveDomainConfigs();
  }

  async getAllDomainConfigs(): Promise<Record<string, any>> {
    await this.loadDomainConfigs();
    return { ...this.domainConfigs };
  }
}

