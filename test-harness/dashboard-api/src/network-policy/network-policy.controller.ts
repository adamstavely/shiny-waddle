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
  async testFirewallRules(@Body(ValidationPipe) dto: { configId?: string; rules?: any[] }) {
    this.logger.log(dto.configId 
      ? `Testing firewall rules with config: ${dto.configId}`
      : `Testing ${dto.rules?.length || 0} firewall rules`);
    return this.networkPolicyService.testFirewallRules(dto);
  }

  @Post('test-service-to-service')
  @HttpCode(HttpStatus.OK)
  async testServiceToService(@Body(ValidationPipe) dto: { configId?: string; source?: string; target?: string }) {
    this.logger.log(dto.configId
      ? `Testing service-to-service with config: ${dto.configId}`
      : `Testing service-to-service: ${dto.source} -> ${dto.target}`);
    return this.networkPolicyService.testServiceToService(dto);
  }

  @Post('validate-segmentation')
  @HttpCode(HttpStatus.OK)
  async validateSegmentation(@Body(ValidationPipe) dto: { configId?: string; segments?: any[] }) {
    this.logger.log(dto.configId
      ? `Validating network segmentation with config: ${dto.configId}`
      : `Validating ${dto.segments?.length || 0} network segments`);
    return this.networkPolicyService.validateSegmentation(dto);
  }

  @Post('test-service-mesh-policies')
  @HttpCode(HttpStatus.OK)
  async testServiceMeshPolicies(@Body(ValidationPipe) dto: { configId?: string; config?: any }) {
    this.logger.log(dto.configId
      ? `Testing service mesh policies with config: ${dto.configId}`
      : `Testing service mesh policies: ${dto.config?.name || 'unknown'}`);
    return this.networkPolicyService.testServiceMeshPolicies(dto);
  }
}

