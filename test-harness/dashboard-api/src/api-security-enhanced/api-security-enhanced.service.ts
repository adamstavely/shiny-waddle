import { Injectable, Logger } from '@nestjs/common';
import { APIVersioningTester, APIVersion } from '../../../services/api-versioning-tester';
import { APIGatewayPolicyValidator, APIGatewayConfig } from '../../../services/api-gateway-policy-validator';
import { WebhookSecurityTester, WebhookConfig } from '../../../services/webhook-security-tester';
import { GraphQLSecurityValidator, GraphQLConfig } from '../../../services/graphql-security-validator';
import { APIContractSecurityTester, APIContract } from '../../../services/api-contract-security-tester';
import { InternalServerException } from '../common/exceptions/business.exception';
import {
  APIVersioningTestDto,
  GatewayPolicyValidationDto,
  WebhookSecurityTestDto,
  GraphQLSecurityTestDto,
  ContractSecurityTestDto,
} from './dto/api-security.dto';

@Injectable()
export class APISecurityEnhancedService {
  private readonly logger = new Logger(APISecurityEnhancedService.name);
  private versioningTester: APIVersioningTester;
  private gatewayValidator: APIGatewayPolicyValidator;
  private webhookTester: WebhookSecurityTester;
  private graphqlValidator: GraphQLSecurityValidator;
  private contractTester: APIContractSecurityTester;

  constructor() {
    this.versioningTester = new APIVersioningTester();
    this.gatewayValidator = new APIGatewayPolicyValidator();
    this.webhookTester = new WebhookSecurityTester();
    this.graphqlValidator = new GraphQLSecurityValidator();
    this.contractTester = new APIContractSecurityTester();
  }

  async testAPIVersioning(dto: APIVersioningTestDto) {
    try {
      const version: APIVersion = {
        version: dto.version,
        endpoint: dto.endpoint,
        deprecated: dto.deprecated || false,
        deprecationDate: dto.deprecationDate ? new Date(dto.deprecationDate) : undefined,
        sunsetDate: dto.sunsetDate ? new Date(dto.sunsetDate) : undefined,
        accessControl: dto.accessControl || {},
      };

      return await this.versioningTester.testVersionDeprecation(version);
    } catch (error: any) {
      this.logger.error(`Error testing API versioning: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to test API versioning', { originalError: error.message });
    }
  }

  async validateGatewayPolicies(dto: GatewayPolicyValidationDto) {
    try {
      const config: APIGatewayConfig = {
        type: dto.type,
        endpoint: dto.endpoint,
        policies: dto.policies || [],
        routes: dto.routes || [],
      };

      return await this.gatewayValidator.validateGatewayPolicies(config);
    } catch (error: any) {
      this.logger.error(`Error validating gateway policies: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to validate gateway policies', { originalError: error.message });
    }
  }

  async testWebhookSecurity(dto: WebhookSecurityTestDto) {
    try {
      const config: WebhookConfig = {
        endpoint: dto.endpoint,
        authentication: dto.authentication,
        encryption: dto.encryption || { enabled: false },
        rateLimiting: dto.rateLimiting,
      };

      return await this.webhookTester.testWebhookAuthentication(config);
    } catch (error: any) {
      this.logger.error(`Error testing webhook security: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to test webhook security', { originalError: error.message });
    }
  }

  async testGraphQLSecurity(dto: GraphQLSecurityTestDto) {
    try {
      const config: GraphQLConfig = {
        endpoint: dto.endpoint,
        schema: dto.schema,
        maxDepth: dto.maxDepth,
        maxComplexity: dto.maxComplexity,
        introspectionEnabled: dto.introspectionEnabled || false,
      };

      return await this.graphqlValidator.testQueryDepthLimits(config);
    } catch (error: any) {
      this.logger.error(`Error testing GraphQL security: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to test GraphQL security', { originalError: error.message });
    }
  }

  async validateContractSecurity(dto: ContractSecurityTestDto) {
    try {
      const contract: APIContract = {
        version: dto.version,
        schema: dto.schema,
        endpoints: dto.endpoints || [],
      };

      return await this.contractTester.validateContractSecurity(contract);
    } catch (error: any) {
      this.logger.error(`Error validating contract security: ${error.message}`, error.stack);
      throw new InternalServerException('Failed to validate contract security', { originalError: error.message });
    }
  }
}

