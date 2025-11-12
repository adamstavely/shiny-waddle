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
  async testFirewallRules(@Body(ValidationPipe) dto: { rules: any[] }) {
    this.logger.log(`Testing ${dto.rules?.length || 0} firewall rules`);
    return this.networkPolicyService.testFirewallRules(dto);
  }

  @Post('test-service-to-service')
  @HttpCode(HttpStatus.OK)
  async testServiceToService(@Body(ValidationPipe) dto: { source: string; target: string }) {
    this.logger.log(`Testing service-to-service: ${dto.source} -> ${dto.target}`);
    return this.networkPolicyService.testServiceToService(dto);
  }

  @Post('validate-segmentation')
  @HttpCode(HttpStatus.OK)
  async validateSegmentation(@Body(ValidationPipe) dto: { segments: any[] }) {
    this.logger.log(`Validating ${dto.segments?.length || 0} network segments`);
    return this.networkPolicyService.validateSegmentation(dto);
  }

  @Post('test-service-mesh-policies')
  @HttpCode(HttpStatus.OK)
  async testServiceMeshPolicies(@Body(ValidationPipe) dto: { config: any }) {
    this.logger.log(`Testing service mesh policies: ${dto.config?.name || 'unknown'}`);
    return this.networkPolicyService.testServiceMeshPolicies(dto);
  }
}

