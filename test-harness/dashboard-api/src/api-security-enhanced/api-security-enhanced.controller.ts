import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { APISecurityEnhancedService } from './api-security-enhanced.service';
import {
  APIVersioningTestDto,
  GatewayPolicyValidationDto,
  WebhookSecurityTestDto,
  GraphQLSecurityTestDto,
  ContractSecurityTestDto,
} from './dto/api-security.dto';

@Controller('api/api-security')
export class APISecurityEnhancedController {
  private readonly logger = new Logger(APISecurityEnhancedController.name);

  constructor(private readonly service: APISecurityEnhancedService) {}

  @Post('versioning')
  @HttpCode(HttpStatus.OK)
  async testAPIVersioning(@Body(ValidationPipe) dto: APIVersioningTestDto) {
    this.logger.log(`Testing API versioning: ${dto.version}`);
    return this.service.testAPIVersioning(dto);
  }

  @Post('gateway-policies')
  @HttpCode(HttpStatus.OK)
  async validateGatewayPolicies(@Body(ValidationPipe) dto: GatewayPolicyValidationDto) {
    this.logger.log(`Validating gateway policies: ${dto.type}`);
    return this.service.validateGatewayPolicies(dto);
  }

  @Post('webhooks')
  @HttpCode(HttpStatus.OK)
  async testWebhookSecurity(@Body(ValidationPipe) dto: WebhookSecurityTestDto) {
    this.logger.log(`Testing webhook security: ${dto.endpoint}`);
    return this.service.testWebhookSecurity(dto);
  }

  @Post('graphql')
  @HttpCode(HttpStatus.OK)
  async testGraphQLSecurity(@Body(ValidationPipe) dto: GraphQLSecurityTestDto) {
    this.logger.log(`Testing GraphQL security: ${dto.endpoint}`);
    return this.service.testGraphQLSecurity(dto);
  }

  @Post('contracts')
  @HttpCode(HttpStatus.OK)
  async validateContractSecurity(@Body(ValidationPipe) dto: ContractSecurityTestDto) {
    this.logger.log(`Validating contract security: ${dto.version}`);
    return this.service.validateContractSecurity(dto);
  }
}

