import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { IdentityProviderService } from './identity-provider.service';

@Controller('api/identity-providers')
export class IdentityProviderController {
  private readonly logger = new Logger(IdentityProviderController.name);

  constructor(private readonly identityProviderService: IdentityProviderService) {}

  @Post('test-ad-group')
  @HttpCode(HttpStatus.OK)
  async testADGroup(@Body(ValidationPipe) dto: { user: any; group: string }) {
    this.logger.log(`Testing AD group: ${dto.group} for user: ${dto.user?.id || 'unknown'}`);
    return this.identityProviderService.testADGroup(dto);
  }

  @Post('test-okta-policy')
  @HttpCode(HttpStatus.OK)
  async testOktaPolicy(@Body(ValidationPipe) dto: { policy: any }) {
    this.logger.log(`Testing Okta policy: ${dto.policy?.policyId || 'unknown'}`);
    return this.identityProviderService.testOktaPolicy(dto);
  }

  @Post('test-auth0-policy')
  @HttpCode(HttpStatus.OK)
  async testAuth0Policy(@Body(ValidationPipe) dto: { policy: any }) {
    this.logger.log(`Testing Auth0 policy`);
    return this.identityProviderService.testAuth0Policy(dto);
  }

  @Post('test-azure-ad-conditional-access')
  @HttpCode(HttpStatus.OK)
  async testAzureADConditionalAccess(@Body(ValidationPipe) dto: { policy: any }) {
    this.logger.log(`Testing Azure AD conditional access policy: ${dto.policy?.id || 'unknown'}`);
    return this.identityProviderService.testAzureADConditionalAccess(dto);
  }

  @Post('test-gcp-iam-binding')
  @HttpCode(HttpStatus.OK)
  async testGCPIAMBinding(@Body(ValidationPipe) dto: { binding: any }) {
    this.logger.log(
      `Testing GCP IAM binding: ${dto.binding?.resource || 'unknown'} - ${dto.binding?.role || 'unknown'}`,
    );
    return this.identityProviderService.testGCPIAMBinding(dto);
  }

  @Post('validate-policy-sync')
  @HttpCode(HttpStatus.OK)
  async validatePolicySync(@Body(ValidationPipe) dto: { source: any; target: any }) {
    this.logger.log(
      `Validating policy sync: ${dto.source?.type || 'unknown'} -> ${dto.target?.type || 'unknown'}`,
    );
    return this.identityProviderService.validatePolicySync(dto);
  }
}

