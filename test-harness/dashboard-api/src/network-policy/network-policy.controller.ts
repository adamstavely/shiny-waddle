import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { NetworkPolicyService } from './network-policy.service';

@Controller('api/network-policy')
export class NetworkPolicyController {
  private readonly logger = new Logger(NetworkPolicyController.name);

  constructor(private readonly networkPolicyService: NetworkPolicyService) {}

  @Post('test-firewall-rules')
  @HttpCode(HttpStatus.OK)
  async testFirewallRules(@Body(ValidationPipe) dto: { applicationId?: string; networkSegmentId?: string; rules?: any[] }) {
    this.logger.log(dto.applicationId 
      ? `Testing firewall rules for application: ${dto.applicationId}${dto.networkSegmentId ? `, segment: ${dto.networkSegmentId}` : ''}`
      : `Testing ${dto.rules?.length || 0} firewall rules`);
    return this.networkPolicyService.testFirewallRules(dto);
  }

  @Post('test-service-to-service')
  @HttpCode(HttpStatus.OK)
  async testServiceToService(@Body(ValidationPipe) dto: { applicationId?: string; networkSegmentId?: string; source?: string; target?: string }) {
    this.logger.log(dto.applicationId
      ? `Testing service-to-service for application: ${dto.applicationId}${dto.networkSegmentId ? `, segment: ${dto.networkSegmentId}` : ''}`
      : `Testing service-to-service: ${dto.source} -> ${dto.target}`);
    return this.networkPolicyService.testServiceToService(dto);
  }

  @Post('validate-segmentation')
  @HttpCode(HttpStatus.OK)
  async validateSegmentation(@Body(ValidationPipe) dto: { applicationId?: string; segments?: any[] }) {
    this.logger.log(dto.applicationId
      ? `Validating network segmentation for application: ${dto.applicationId}`
      : `Validating ${dto.segments?.length || 0} network segments`);
    return this.networkPolicyService.validateSegmentation(dto);
  }

  @Post('test-service-mesh-policies')
  @HttpCode(HttpStatus.OK)
  async testServiceMeshPolicies(@Body(ValidationPipe) dto: { applicationId?: string; networkSegmentId?: string; config?: any }) {
    this.logger.log(dto.applicationId
      ? `Testing service mesh policies for application: ${dto.applicationId}${dto.networkSegmentId ? `, segment: ${dto.networkSegmentId}` : ''}`
      : `Testing service mesh policies: ${dto.config?.name || 'unknown'}`);
    return this.networkPolicyService.testServiceMeshPolicies(dto);
  }
}

