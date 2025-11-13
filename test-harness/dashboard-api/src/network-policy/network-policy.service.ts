import { Injectable, Logger, NotFoundException, Inject, forwardRef } from '@nestjs/common';
import { NetworkMicrosegmentationTester } from '../../../services/network-microsegmentation-tester';
import { ServiceMeshConfig } from '../../../services/service-mesh-integration';
import { FirewallRule, NetworkSegment } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { NetworkPolicyConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';
import { validateNetworkPolicyConfig, formatValidationErrors } from '../test-configurations/utils/configuration-validator';

@Injectable()
export class NetworkPolicyService {
  private readonly logger = new Logger(NetworkPolicyService.name);
  private tester: NetworkMicrosegmentationTester;

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly configService: TestConfigurationsService,
  ) {
    this.tester = new NetworkMicrosegmentationTester();
  }

  async testFirewallRules(dto: { configId?: string; rules?: FirewallRule[] }) {
    try {
      let rules: FirewallRule[];
      let npConfig: NetworkPolicyConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'network-policy') {
          throw new ValidationException(`Configuration ${dto.configId} is not a network policy configuration`);
        }
        npConfig = config as NetworkPolicyConfigurationEntity;
        
        // Validate configuration completeness
        const validationErrors = validateNetworkPolicyConfig(npConfig);
        if (validationErrors.length > 0) {
          const errorMessage = formatValidationErrors(validationErrors, npConfig.name);
          throw new ValidationException(
            `Configuration '${npConfig.name}' is missing required fields for firewall rules test:\n${errorMessage}`
          );
        }
        
        rules = npConfig.firewallRules;
        // Merge with inline rules if provided (inline takes precedence)
        if (dto.rules && dto.rules.length > 0) {
          rules = dto.rules;
        }
      } else if (dto.rules) {
        rules = dto.rules;
      } else {
        throw new ValidationException(
          'Either configId or rules must be provided. If using configId, ensure the configuration includes firewallRules.'
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
      if (npConfig?.testLogic) {
        // Apply validateConnectivity flag
        if (npConfig.testLogic.validateConnectivity !== false) {
          result.connectivityValidated = result.passed || false;
        }

        // Run custom rules if present
        if (npConfig.testLogic.customRules && npConfig.testLogic.customRules.length > 0) {
          result.customRuleResults = npConfig.testLogic.customRules.map(rule => ({
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

  async testServiceToService(dto: { configId?: string; source?: string; target?: string }) {
    try {
      let source: string;
      let target: string;
      let npConfig: NetworkPolicyConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'network-policy') {
          throw new ValidationException(`Configuration ${dto.configId} is not a network policy configuration`);
        }
        npConfig = config as NetworkPolicyConfigurationEntity;
        // Use network segments to determine source/target if not provided
        if (npConfig.networkSegments && npConfig.networkSegments.length >= 2) {
          source = dto.source || npConfig.networkSegments[0].services[0] || 'frontend';
          target = dto.target || npConfig.networkSegments[1].services[0] || 'backend';
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
      if (npConfig?.testLogic) {
        // Apply validateConnectivity flag
        if (npConfig.testLogic.validateConnectivity !== false) {
          result.connectivityValidated = result.passed || false;
        }

        // Run custom rules if present
        if (npConfig.testLogic.customRules && npConfig.testLogic.customRules.length > 0) {
          result.customRuleResults = npConfig.testLogic.customRules.map(rule => ({
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

  async validateSegmentation(dto: { configId?: string; segments?: NetworkSegment[] }) {
    try {
      let segments: NetworkSegment[];
      let npConfig: NetworkPolicyConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'network-policy') {
          throw new ValidationException(`Configuration ${dto.configId} is not a network policy configuration`);
        }
        npConfig = config as NetworkPolicyConfigurationEntity;
        
        // Validate configuration completeness
        const validationErrors = validateNetworkPolicyConfig(npConfig);
        if (validationErrors.length > 0) {
          const errorMessage = formatValidationErrors(validationErrors, npConfig.name);
          throw new ValidationException(
            `Configuration '${npConfig.name}' is missing required fields for network segmentation test:\n${errorMessage}`
          );
        }
        
        segments = npConfig.networkSegments;
        // Merge with inline segments if provided (inline takes precedence)
        if (dto.segments && dto.segments.length > 0) {
          segments = dto.segments;
        }
      } else if (dto.segments) {
        segments = dto.segments;
      } else {
        throw new ValidationException('Either configId or segments must be provided');
      }

      if (!segments || !Array.isArray(segments)) {
        throw new ValidationException('Network segments array is required');
      }
      if (segments.length === 0) {
        throw new ValidationException('At least one network segment is required');
      }

      const result = await this.tester.validateNetworkSegmentation(segments);

      // Apply testLogic if config provided
      if (npConfig?.testLogic) {
        // Apply checkSegmentation flag
        if (npConfig.testLogic.checkSegmentation !== false) {
          result.segmentationChecked = result.passed || false;
        }

        // Run custom rules if present
        if (npConfig.testLogic.customRules && npConfig.testLogic.customRules.length > 0) {
          result.customRuleResults = npConfig.testLogic.customRules.map(rule => ({
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

  async testServiceMeshPolicies(dto: { configId?: string; config?: ServiceMeshConfig }) {
    try {
      let meshConfig: ServiceMeshConfig;
      let npConfig: NetworkPolicyConfigurationEntity | null = null;

      if (dto.configId) {
        const config = await this.configService.findOne(dto.configId);
        if (config.type !== 'network-policy') {
          throw new ValidationException(`Configuration ${dto.configId} is not a network policy configuration`);
        }
        npConfig = config as NetworkPolicyConfigurationEntity;
        // Use serviceMeshConfig from config if available
        if (npConfig.serviceMeshConfig) {
          meshConfig = npConfig.serviceMeshConfig;
          // Merge with inline config if provided (inline takes precedence)
          if (dto.config) {
            meshConfig = { ...meshConfig, ...dto.config };
          }
        } else if (dto.config) {
          meshConfig = dto.config;
        } else {
          throw new ValidationException('Service mesh configuration is required (either in config or request)');
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
      if (npConfig?.testLogic) {
        // Run custom rules if present
        if (npConfig.testLogic.customRules && npConfig.testLogic.customRules.length > 0) {
          result.customRuleResults = npConfig.testLogic.customRules.map(rule => ({
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

