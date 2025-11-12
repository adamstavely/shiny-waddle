import { Injectable, Logger } from '@nestjs/common';
import { NetworkMicrosegmentationTester } from '../../../services/network-microsegmentation-tester';
import { ServiceMeshConfig, FirewallRule, NetworkSegment } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class NetworkPolicyService {
  private readonly logger = new Logger(NetworkPolicyService.name);
  private tester: NetworkMicrosegmentationTester;

  constructor() {
    this.tester = new NetworkMicrosegmentationTester();
  }

  async testFirewallRules(dto: { rules: FirewallRule[] }) {
    try {
      if (!dto.rules || !Array.isArray(dto.rules)) {
        throw new ValidationException('Firewall rules array is required');
      }
      if (dto.rules.length === 0) {
        throw new ValidationException('At least one firewall rule is required');
      }
      return await this.tester.testFirewallRules(dto.rules);
    } catch (error: any) {
      this.logger.error(`Error testing firewall rules: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test firewall rules',
        { originalError: error.message },
      );
    }
  }

  async testServiceToService(dto: { source: string; target: string }) {
    try {
      if (!dto.source || typeof dto.source !== 'string') {
        throw new ValidationException('Source service name is required');
      }
      if (!dto.target || typeof dto.target !== 'string') {
        throw new ValidationException('Target service name is required');
      }
      if (dto.source === dto.target) {
        throw new ValidationException('Source and target must be different');
      }
      return await this.tester.testServiceToServiceTraffic(dto.source, dto.target);
    } catch (error: any) {
      this.logger.error(`Error testing service-to-service traffic: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test service-to-service traffic',
        { originalError: error.message },
      );
    }
  }

  async validateSegmentation(dto: { segments: NetworkSegment[] }) {
    try {
      if (!dto.segments || !Array.isArray(dto.segments)) {
        throw new ValidationException('Network segments array is required');
      }
      if (dto.segments.length === 0) {
        throw new ValidationException('At least one network segment is required');
      }
      return await this.tester.validateNetworkSegmentation(dto.segments);
    } catch (error: any) {
      this.logger.error(`Error validating network segmentation: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate network segmentation',
        { originalError: error.message },
      );
    }
  }

  async testServiceMeshPolicies(dto: { config: ServiceMeshConfig }) {
    try {
      if (!dto.config) {
        throw new ValidationException('Service mesh configuration is required');
      }
      if (!dto.config.name) {
        throw new ValidationException('Service mesh name is required');
      }
      return await this.tester.testServiceMeshPolicies(dto.config);
    } catch (error: any) {
      this.logger.error(`Error testing service mesh policies: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test service mesh policies',
        { originalError: error.message },
      );
    }
  }
}

