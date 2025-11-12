import { Injectable, NotFoundException, BadRequestException, Logger, Inject, forwardRef } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  TestConfigurationEntity,
  TestConfigurationType,
  RLSCLSConfigurationEntity,
  NetworkPolicyConfigurationEntity,
  DLPConfigurationEntity,
  IdentityLifecycleConfigurationEntity,
  APIGatewayConfigurationEntity,
  DistributedSystemsConfigurationEntity,
} from './entities/test-configuration.entity';
import {
  CreateTestConfigurationDto,
  CreateRLSCLSConfigurationDto,
  CreateNetworkPolicyConfigurationDto,
  CreateDLPConfigurationDto,
  CreateIdentityLifecycleConfigurationDto,
  CreateAPIGatewayConfigurationDto,
  CreateDistributedSystemsConfigurationDto,
} from './dto/create-test-configuration.dto';
import { RLSCLSService } from '../rls-cls/rls-cls.service';
import { DLPService } from '../dlp/dlp.service';
import { IdentityLifecycleService } from '../identity-lifecycle/identity-lifecycle.service';
import { APIGatewayService } from '../api-gateway/api-gateway.service';
import { NetworkPolicyService } from '../network-policy/network-policy.service';
import { DistributedSystemsService } from '../distributed-systems/distributed-systems.service';

@Injectable()
export class TestConfigurationsService {
  private readonly logger = new Logger(TestConfigurationsService.name);
  private readonly configsFile = path.join(process.cwd(), 'data', 'test-configurations.json');
  private configurations: TestConfigurationEntity[] = [];

  constructor(
    @Inject(forwardRef(() => RLSCLSService))
    private readonly rlsClsService: RLSCLSService,
    @Inject(forwardRef(() => DLPService))
    private readonly dlpService: DLPService,
    @Inject(forwardRef(() => IdentityLifecycleService))
    private readonly identityLifecycleService: IdentityLifecycleService,
    @Inject(forwardRef(() => APIGatewayService))
    private readonly apiGatewayService: APIGatewayService,
    @Inject(forwardRef(() => NetworkPolicyService))
    private readonly networkPolicyService: NetworkPolicyService,
    @Inject(forwardRef(() => DistributedSystemsService))
    private readonly distributedSystemsService: DistributedSystemsService,
  ) {
    this.loadConfigurations().catch(err => {
      this.logger.error('Error loading test configurations on startup:', err);
    });
  }

  private async loadConfigurations(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.configsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.configurations = (Array.isArray(parsed) ? parsed : []).map((c: any) => ({
          ...c,
          createdAt: new Date(c.createdAt),
          updatedAt: new Date(c.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.configurations = [];
          await this.initializeDefaultConfigurations();
          await this.saveConfigurations();
        } else {
          throw readError;
        }
      }
      
      // Initialize defaults if no configurations exist
      if (this.configurations.length === 0) {
        await this.initializeDefaultConfigurations();
        await this.saveConfigurations();
      }
    } catch (error) {
      this.logger.error('Error loading test configurations:', error);
      this.configurations = [];
    }
  }

  private async initializeDefaultConfigurations(): Promise<void> {
    const now = new Date();
    
    // Default RLS/CLS Configuration
    const defaultRLSCLS: RLSCLSConfigurationEntity = {
      id: uuidv4(),
      name: 'Default PostgreSQL RLS/CLS',
      type: 'rls-cls',
      description: 'Default configuration for PostgreSQL RLS/CLS testing',
      database: {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'test',
        username: 'postgres',
      },
      testQueries: [
        {
          name: 'test-user-query',
          sql: 'SELECT * FROM users WHERE tenant_id = ?',
        },
      ],
      validationRules: {
        minRLSCoverage: 80,
        minCLSCoverage: 80,
      },
      testLogic: {
        skipDisabledPolicies: true,
        validateCrossTenant: true,
      },
      createdAt: now,
      updatedAt: now,
    };

    // Default Network Policy Configuration
    const defaultNetworkPolicy: NetworkPolicyConfigurationEntity = {
      id: uuidv4(),
      name: 'Default Network Segmentation',
      type: 'network-policy',
      description: 'Default configuration for network policy testing',
      firewallRules: [
        {
          id: 'default-allow-frontend-backend',
          name: 'Allow Frontend to Backend',
          source: '10.0.1.0/24',
          destination: '10.0.2.0/24',
          protocol: 'tcp',
          port: 8080,
          action: 'allow',
          enabled: true,
        },
      ],
      networkSegments: [
        {
          id: 'default-frontend-segment',
          name: 'Frontend Segment',
          cidr: '10.0.1.0/24',
          services: ['frontend'],
          allowedConnections: ['backend'],
          deniedConnections: ['database'],
        },
      ],
      testLogic: {
        validateConnectivity: true,
        checkSegmentation: true,
      },
      createdAt: now,
      updatedAt: now,
    };

    // Default DLP Configuration
    const defaultDLP: DLPConfigurationEntity = {
      id: uuidv4(),
      name: 'Default DLP Patterns',
      type: 'dlp',
      description: 'Default configuration for DLP testing',
      patterns: [
        {
          name: 'SSN Pattern',
          pattern: '\\d{3}-\\d{2}-\\d{4}',
          type: 'ssn',
        },
        {
          name: 'Credit Card Pattern',
          pattern: '\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}',
          type: 'credit-card',
        },
      ],
      bulkExportLimits: {
        csv: 10000,
        json: 10000,
        excel: 10000,
        api: 1000,
      },
      testLogic: {
        validateAPIResponses: true,
        checkBulkExports: true,
      },
      createdAt: now,
      updatedAt: now,
    };

    // Default Identity Lifecycle Configuration
    const defaultIdentityLifecycle: IdentityLifecycleConfigurationEntity = {
      id: uuidv4(),
      name: 'Default Identity Lifecycle',
      type: 'identity-lifecycle',
      description: 'Default configuration for identity lifecycle testing',
      onboardingWorkflow: {
        steps: [
          { name: 'create-account', required: true },
          { name: 'assign-role', required: true },
          { name: 'enable-mfa', required: true },
        ],
      },
      pamConfig: {
        maxJITDuration: 60,
        requireApproval: true,
        emergencyAccessEnabled: true,
      },
      credentialRotationRules: {
        passwordMaxAge: 90,
        apiKeyMaxAge: 365,
        requireMFA: true,
      },
      createdAt: now,
      updatedAt: now,
    };

    // Default API Gateway Configuration
    const defaultAPIGateway: APIGatewayConfigurationEntity = {
      id: uuidv4(),
      name: 'Default API Gateway',
      type: 'api-gateway',
      description: 'Default configuration for API gateway testing',
      gatewayPolicies: [
        {
          id: 'default-api-policy',
          name: 'Default API Policy',
          endpoint: '/api/*',
          method: 'GET',
          rules: [],
        },
      ],
      rateLimitConfig: {
        defaultLimit: 100,
        defaultTimeWindow: 60,
        perEndpointLimits: {},
      },
      serviceAuthConfig: {
        methods: ['api-key', 'mtls'],
        requiredForEndpoints: [],
      },
      createdAt: now,
      updatedAt: now,
    };

    this.configurations = [
      defaultRLSCLS,
      defaultNetworkPolicy,
      defaultDLP,
      defaultIdentityLifecycle,
      defaultAPIGateway,
    ];
    
    this.logger.log('Initialized default test configurations');
  }

  private async saveConfigurations(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      await fs.writeFile(this.configsFile, JSON.stringify(this.configurations, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving test configurations:', error);
      throw error;
    }
  }

  async findAll(type?: TestConfigurationType): Promise<TestConfigurationEntity[]> {
    await this.loadConfigurations();
    if (type) {
      return this.configurations.filter(c => c.type === type);
    }
    return this.configurations;
  }

  async findOne(id: string): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const config = this.configurations.find(c => c.id === id);
    if (!config) {
      throw new NotFoundException(`Test configuration with ID ${id} not found`);
    }
    return config;
  }

  async create(dto: CreateTestConfigurationDto): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();

    // Check for duplicate name
    const existing = this.configurations.find(c => c.name === dto.name && c.type === dto.type);
    if (existing) {
      throw new BadRequestException(`Configuration with name "${dto.name}" and type "${dto.type}" already exists`);
    }

    const now = new Date();
    let newConfig: TestConfigurationEntity;

    switch (dto.type) {
      case 'rls-cls': {
        const rlsDto = dto as CreateRLSCLSConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: rlsDto.name,
          type: 'rls-cls',
          description: rlsDto.description,
          tags: rlsDto.tags || [],
          database: rlsDto.database,
          testQueries: rlsDto.testQueries,
          validationRules: rlsDto.validationRules,
          testLogic: rlsDto.testLogic,
          createdAt: now,
          updatedAt: now,
        } as RLSCLSConfigurationEntity;
        break;
      }
      case 'network-policy': {
        const npDto = dto as CreateNetworkPolicyConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: npDto.name,
          type: 'network-policy',
          description: npDto.description,
          tags: npDto.tags || [],
          firewallRules: npDto.firewallRules,
          networkSegments: npDto.networkSegments,
          serviceMeshConfig: npDto.serviceMeshConfig,
          testLogic: npDto.testLogic,
          createdAt: now,
          updatedAt: now,
        } as NetworkPolicyConfigurationEntity;
        break;
      }
      case 'dlp': {
        const dlpDto = dto as CreateDLPConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: dlpDto.name,
          type: 'dlp',
          description: dlpDto.description,
          tags: dlpDto.tags || [],
          patterns: dlpDto.patterns,
          bulkExportLimits: dlpDto.bulkExportLimits,
          piiDetectionRules: dlpDto.piiDetectionRules,
          testLogic: dlpDto.testLogic,
          createdAt: now,
          updatedAt: now,
        } as DLPConfigurationEntity;
        break;
      }
      case 'identity-lifecycle': {
        const ilDto = dto as CreateIdentityLifecycleConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: ilDto.name,
          type: 'identity-lifecycle',
          description: ilDto.description,
          tags: ilDto.tags || [],
          onboardingWorkflow: ilDto.onboardingWorkflow,
          pamConfig: ilDto.pamConfig,
          credentialRotationRules: ilDto.credentialRotationRules,
          testLogic: ilDto.testLogic,
          createdAt: now,
          updatedAt: now,
        } as IdentityLifecycleConfigurationEntity;
        break;
      }
      case 'api-gateway': {
        const agDto = dto as CreateAPIGatewayConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: agDto.name,
          type: 'api-gateway',
          description: agDto.description,
          tags: agDto.tags || [],
          rateLimitConfig: agDto.rateLimitConfig,
          serviceAuthConfig: agDto.serviceAuthConfig,
          gatewayPolicies: agDto.gatewayPolicies,
          testLogic: agDto.testLogic,
          createdAt: now,
          updatedAt: now,
        } as APIGatewayConfigurationEntity;
        break;
      }
      case 'distributed-systems': {
        const dsDto = dto as CreateDistributedSystemsConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: dsDto.name,
          type: 'distributed-systems',
          description: dsDto.description,
          tags: dsDto.tags || [],
          regions: dsDto.regions,
          policySync: dsDto.policySync,
          coordination: dsDto.coordination,
          testLogic: dsDto.testLogic,
          createdAt: now,
          updatedAt: now,
        } as DistributedSystemsConfigurationEntity;
        break;
      }
      default:
        throw new BadRequestException(`Unknown configuration type: ${(dto as any).type}`);
    }

    this.configurations.push(newConfig);
    await this.saveConfigurations();
    this.logger.log(`Created test configuration: ${newConfig.id} (${newConfig.type})`);
    return newConfig;
  }

  async update(id: string, dto: Partial<CreateTestConfigurationDto>): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const index = this.configurations.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test configuration with ID ${id} not found`);
    }

    const existing = this.configurations[index];
    
    // Check for duplicate name if name is being changed
    if (dto.name && dto.name !== existing.name) {
      const duplicate = this.configurations.find(
        c => c.name === dto.name && c.type === existing.type && c.id !== id
      );
      if (duplicate) {
        throw new BadRequestException(`Configuration with name "${dto.name}" and type "${existing.type}" already exists`);
      }
    }

    const updated = {
      ...existing,
      ...dto,
      id: existing.id, // Don't allow ID changes
      type: existing.type, // Don't allow type changes
      updatedAt: new Date(),
    } as TestConfigurationEntity;

    this.configurations[index] = updated;
    await this.saveConfigurations();
    this.logger.log(`Updated test configuration: ${id}`);
    return updated;
  }

  async delete(id: string): Promise<void> {
    await this.loadConfigurations();
    const index = this.configurations.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test configuration with ID ${id} not found`);
    }

    this.configurations.splice(index, 1);
    await this.saveConfigurations();
    this.logger.log(`Deleted test configuration: ${id}`);
  }

  async duplicate(id: string, newName?: string): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const original = await this.findOne(id);
    
    const duplicated = {
      ...original,
      id: uuidv4(),
      name: newName || `${original.name} (Copy)`,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.configurations.push(duplicated);
    await this.saveConfigurations();
    this.logger.log(`Duplicated test configuration: ${id} -> ${duplicated.id}`);
    return duplicated;
  }

  async testConfiguration(id: string): Promise<any> {
    await this.loadConfigurations();
    const config = await this.findOne(id);

    this.logger.log(`Testing configuration: ${id} (${config.type})`);

    try {
      switch (config.type) {
        case 'rls-cls': {
          const rlsConfig = config as RLSCLSConfigurationEntity;
          // Run RLS coverage test as the primary test
          return await this.rlsClsService.testRLSCoverage({ configId: id });
        }
        case 'network-policy': {
          const npConfig = config as NetworkPolicyConfigurationEntity;
          // Run firewall rules test as the primary test
          return await this.networkPolicyService.testFirewallRules({ configId: id });
        }
        case 'dlp': {
          const dlpConfig = config as DLPConfigurationEntity;
          // Run exfiltration test as the primary test
          return await this.dlpService.testExfiltration({ configId: id });
        }
        case 'identity-lifecycle': {
          const ilConfig = config as IdentityLifecycleConfigurationEntity;
          // Run onboarding test as the primary test
          return await this.identityLifecycleService.testOnboarding({ configId: id });
        }
        case 'api-gateway': {
          const agConfig = config as APIGatewayConfigurationEntity;
          // Run rate limiting test as the primary test
          return await this.apiGatewayService.testRateLimiting({ configId: id });
        }
        case 'distributed-systems': {
          const dsConfig = config as DistributedSystemsConfigurationEntity;
          // Run a multi-region test as the primary test
          return await this.distributedSystemsService.runTest({
            name: `Test: ${dsConfig.name}`,
            testType: 'multi-region',
            configId: id,
          });
        }
        default:
          throw new BadRequestException(`Unknown configuration type: ${(config as any).type}`);
      }
    } catch (error: any) {
      this.logger.error(`Error testing configuration ${id}: ${error.message}`, error.stack);
      throw error;
    }
  }
}

