import { Injectable, Logger, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { NetworkMicrosegmentationTester } from '../../../heimdall-framework/services/network-microsegmentation-tester';
import { ServiceMeshConfig } from '../../../heimdall-framework/services/service-mesh-integration';
import { FirewallRule, NetworkSegment } from '../../../heimdall-framework/core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { ApplicationsService } from '../applications/applications.service';
import { NetworkSegmentInfrastructure } from '../applications/entities/application.entity';
import { validateNetworkPolicyConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class NetworkPolicyService {
  private readonly logger = new Logger(NetworkPolicyService.name);
  private tester: NetworkMicrosegmentationTester;

  constructor(
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService,
  ) {
    this.tester = new NetworkMicrosegmentationTester();
  }

  async testFirewallRules(dto: { applicationId?: string; networkSegmentId?: string; rules?: FirewallRule[] }) {
    try {
      let rules: FirewallRule[];
      let segmentInfra: NetworkSegmentInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.networkSegments || application.infrastructure.networkSegments.length === 0) {
          throw new ValidationException('Application has no network segment infrastructure configured');
        }
        
        // Find specific segment or use first one
        if (dto.networkSegmentId) {
          segmentInfra = application.infrastructure.networkSegments.find(seg => seg.id === dto.networkSegmentId);
          if (!segmentInfra) {
            throw new NotFoundException(`Network segment ${dto.networkSegmentId} not found in application infrastructure`);
          }
        } else {
          segmentInfra = application.infrastructure.networkSegments[0];
        }
        
        // Extract firewall rules from segment
        rules = segmentInfra.firewallRules || [];
        
        // Merge with inline rules if provided (inline takes precedence)
        if (dto.rules && dto.rules.length > 0) {
          rules = dto.rules;
        }
        
        // Validate configuration completeness
        const validationErrors = validateNetworkPolicyConfig({
          id: segmentInfra.id,
          name: segmentInfra.name,
          type: 'network-policy' as const,
          firewallRules: rules,
          networkSegments: application.infrastructure.networkSegments.map(seg => ({
            id: seg.id,
            name: seg.name,
            cidr: seg.cidr,
            services: [],
            allowedConnections: [],
            deniedConnections: [],
          })),
          serviceMeshConfig: segmentInfra.serviceMeshConfig,
          testLogic: segmentInfra.testLogic,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        if (validationErrors.length > 0) {
          const errorMessage = formatValidationErrors(validationErrors, segmentInfra.name);
          throw new ValidationException(
            `Network segment '${segmentInfra.name}' is missing required fields for firewall rules test:\n${errorMessage}`
          );
        }
      } else if (dto.rules) {
        rules = dto.rules;
      } else {
        throw new ValidationException(
          'Either applicationId or rules must be provided. If using applicationId, ensure the application has network segment infrastructure with firewall rules.'
        );
      }

      if (!rules || !Array.isArray(rules)) {
        throw new ValidationException('Firewall rules array is required');
      }
      if (rules.length === 0) {
        throw new ValidationException('At least one firewall rule is required');
      }

      const result = await this.tester.testFirewallRules(rules);

      // Apply testLogic if config provided
      if (segmentInfra?.testLogic) {
        // Apply validateConnectivity flag
        if (segmentInfra.testLogic.validateConnectivity !== false) {
          result.connectivityValidated = result.passed || false;
        }

        // Run custom rules if present
        if (segmentInfra.testLogic.customRules && segmentInfra.testLogic.customRules.length > 0) {
          result.customRuleResults = segmentInfra.testLogic.customRules.map(rule => ({
            source: rule.source,
            target: rule.target,
            expected: rule.expected,
            actual: this.checkConnectivity(rule.source, rule.target, result),
            passed: this.checkConnectivity(rule.source, rule.target, result) === rule.expected,
            description: rule.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing firewall rules: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test firewall rules',
        { originalError: error.message },
      );
    }
  }

  async testServiceToService(dto: { applicationId?: string; networkSegmentId?: string; source?: string; target?: string }) {
    try {
      let source: string;
      let target: string;
      let segmentInfra: NetworkSegmentInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.networkSegments || application.infrastructure.networkSegments.length === 0) {
          throw new ValidationException('Application has no network segment infrastructure configured');
        }
        
        // Find specific segment or use first one
        if (dto.networkSegmentId) {
          segmentInfra = application.infrastructure.networkSegments.find(seg => seg.id === dto.networkSegmentId);
          if (!segmentInfra) {
            throw new NotFoundException(`Network segment ${dto.networkSegmentId} not found in application infrastructure`);
          }
        } else {
          segmentInfra = application.infrastructure.networkSegments[0];
        }
        
        // Use network segments to determine source/target if not provided
        if (application.infrastructure.networkSegments.length >= 2) {
          source = dto.source || 'frontend';
          target = dto.target || 'backend';
        } else {
          source = dto.source || 'frontend';
          target = dto.target || 'backend';
        }
      } else {
        source = dto.source!;
        target = dto.target!;
      }

      if (!source || typeof source !== 'string') {
        throw new ValidationException('Source service name is required');
      }
      if (!target || typeof target !== 'string') {
        throw new ValidationException('Target service name is required');
      }
      if (source === target) {
        throw new ValidationException('Source and target must be different');
      }

      const result = await this.tester.testServiceToServiceTraffic(source, target);

      // Apply testLogic if config provided
      if (segmentInfra?.testLogic) {
        // Apply validateConnectivity flag
        if (segmentInfra.testLogic.validateConnectivity !== false) {
          result.connectivityValidated = result.passed || false;
        }

        // Run custom rules if present
        if (segmentInfra.testLogic.customRules && segmentInfra.testLogic.customRules.length > 0) {
          result.customRuleResults = segmentInfra.testLogic.customRules.map(rule => ({
            source: rule.source,
            target: rule.target,
            expected: rule.expected,
            actual: result.passed || false,
            passed: (result.passed || false) === rule.expected,
            description: rule.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing service-to-service traffic: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test service-to-service traffic',
        { originalError: error.message },
      );
    }
  }

  async validateSegmentation(dto: { applicationId?: string; segments?: NetworkSegment[] }) {
    try {
      let segments: NetworkSegment[];
      let segmentInfra: NetworkSegmentInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.networkSegments || application.infrastructure.networkSegments.length === 0) {
          throw new ValidationException('Application has no network segment infrastructure configured');
        }
        
        // Convert infrastructure segments to NetworkSegment format
        segments = application.infrastructure.networkSegments.map(seg => ({
          id: seg.id,
          name: seg.name,
          cidr: seg.cidr,
          services: [],
          allowedConnections: [],
          deniedConnections: [],
        }));
        
        // Merge with inline segments if provided (inline takes precedence)
        if (dto.segments && dto.segments.length > 0) {
          segments = dto.segments;
        }
        
        // Use first segment for testLogic reference
        segmentInfra = application.infrastructure.networkSegments[0];
        
        // Validate configuration completeness
        const validationErrors = validateNetworkPolicyConfig({
          id: application.id,
          name: application.name,
          type: 'network-policy' as const,
          firewallRules: segmentInfra.firewallRules || [],
          networkSegments: segments,
          serviceMeshConfig: segmentInfra.serviceMeshConfig,
          testLogic: segmentInfra.testLogic,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        if (validationErrors.length > 0) {
          const errorMessage = formatValidationErrors(validationErrors, application.name);
          throw new ValidationException(
            `Network infrastructure for application '${application.name}' is missing required fields for segmentation test:\n${errorMessage}`
          );
        }
      } else if (dto.segments) {
        segments = dto.segments;
      } else {
        throw new ValidationException('Either applicationId or segments must be provided');
      }

      if (!segments || !Array.isArray(segments)) {
        throw new ValidationException('Network segments array is required');
      }
      if (segments.length === 0) {
        throw new ValidationException('At least one network segment is required');
      }

      const result = await this.tester.validateNetworkSegmentation(segments);

      // Apply testLogic if config provided
      if (segmentInfra?.testLogic) {
        // Apply checkSegmentation flag
        if (segmentInfra.testLogic.checkSegmentation !== false) {
          result.segmentationChecked = result.passed || false;
        }

        // Run custom rules if present
        if (segmentInfra.testLogic.customRules && segmentInfra.testLogic.customRules.length > 0) {
          result.customRuleResults = segmentInfra.testLogic.customRules.map(rule => ({
            source: rule.source,
            target: rule.target,
            expected: rule.expected,
            actual: this.checkSegmentation(rule.source, rule.target, segments, result),
            passed: this.checkSegmentation(rule.source, rule.target, segments, result) === rule.expected,
            description: rule.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error validating network segmentation: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate network segmentation',
        { originalError: error.message },
      );
    }
  }

  async testServiceMeshPolicies(dto: { applicationId?: string; networkSegmentId?: string; config?: ServiceMeshConfig }) {
    try {
      let meshConfig: ServiceMeshConfig;
      let segmentInfra: NetworkSegmentInfrastructure | null = null;

      if (dto.applicationId) {
        const application = await this.applicationsService.findOne(dto.applicationId);
        
        if (!application.infrastructure?.networkSegments || application.infrastructure.networkSegments.length === 0) {
          throw new ValidationException('Application has no network segment infrastructure configured');
        }
        
        // Find specific segment or use first one
        if (dto.networkSegmentId) {
          segmentInfra = application.infrastructure.networkSegments.find(seg => seg.id === dto.networkSegmentId);
          if (!segmentInfra) {
            throw new NotFoundException(`Network segment ${dto.networkSegmentId} not found in application infrastructure`);
          }
        } else {
          segmentInfra = application.infrastructure.networkSegments[0];
        }
        
        // Use serviceMeshConfig from infrastructure if available
        if (segmentInfra.serviceMeshConfig) {
          meshConfig = segmentInfra.serviceMeshConfig;
          // Merge with inline config if provided (inline takes precedence)
          if (dto.config) {
            meshConfig = { ...meshConfig, ...dto.config };
          }
        } else if (dto.config) {
          meshConfig = dto.config;
        } else {
          throw new ValidationException('Service mesh configuration is required (either in infrastructure or request)');
        }
      } else {
        meshConfig = dto.config!;
      }

      if (!meshConfig) {
        throw new ValidationException('Service mesh configuration is required');
      }
      if (!meshConfig.type) {
        throw new ValidationException('Service mesh type is required');
      }
      if (!meshConfig.controlPlaneEndpoint) {
        throw new ValidationException('Service mesh control plane endpoint is required');
      }

      const result = await this.tester.testServiceMeshPolicies(meshConfig);

      // Apply testLogic if config provided
      if (segmentInfra?.testLogic) {
        // Run custom rules if present
        if (segmentInfra.testLogic.customRules && segmentInfra.testLogic.customRules.length > 0) {
          result.customRuleResults = segmentInfra.testLogic.customRules.map(rule => ({
            source: rule.source,
            target: rule.target,
            expected: rule.expected,
            actual: result.passed || false,
            passed: (result.passed || false) === rule.expected,
            description: rule.description,
          }));
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing service mesh policies: ${error.message}`, error.stack);
      if (error instanceof ValidationException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test service mesh policies',
        { originalError: error.message },
      );
    }
  }

  private checkConnectivity(source: string, target: string, result: any): boolean {
    // Simple connectivity check based on test result
    // In a real implementation, this would check actual connectivity rules
    return result.passed || false;
  }

  private checkSegmentation(source: string, target: string, segments: NetworkSegment[], result: any): boolean {
    // Check if source and target are in different segments and segmentation is enforced
    const sourceSegment = segments.find(s => s.services.includes(source));
    const targetSegment = segments.find(s => s.services.includes(target));
    
    if (sourceSegment && targetSegment) {
      // Check if connection is denied between segments
      return sourceSegment.deniedConnections?.includes(targetSegment.id || '') || false;
    }
    
    return result.passed || false;
  }
}

