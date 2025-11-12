import { Injectable, Logger } from '@nestjs/common';
import { IdentityProviderTester } from '../../../services/identity-provider-tester';
import {
  User,
  OktaPolicyTest,
  AzureADConditionalAccessPolicy,
  GCPIAMBinding,
} from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class IdentityProviderService {
  private readonly logger = new Logger(IdentityProviderService.name);
  private tester: IdentityProviderTester;

  constructor() {
    this.tester = new IdentityProviderTester();
  }

  async testADGroup(dto: { user: User; group: string }) {
    try {
      this.validateUser(dto.user);
      if (!dto.group || typeof dto.group !== 'string') {
        throw new ValidationException('Group name is required and must be a string');
      }
      return await this.tester.testADGroupMembership(dto.user, dto.group);
    } catch (error: any) {
      this.logger.error(`Error testing AD group: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test AD group membership',
        { originalError: error.message },
      );
    }
  }

  async testOktaPolicy(dto: { policy: OktaPolicyTest }) {
    try {
      if (!dto.policy) {
        throw new ValidationException('Okta policy is required');
      }
      if (!dto.policy.policyId) {
        throw new ValidationException('Okta policy policyId is required');
      }
      return await this.tester.testOktaPolicySync(dto.policy);
    } catch (error: any) {
      this.logger.error(`Error testing Okta policy: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test Okta policy',
        { originalError: error.message },
      );
    }
  }

  async testAuth0Policy(dto: { policy: any }) {
    try {
      if (!dto.policy) {
        throw new ValidationException('Auth0 policy is required');
      }
      return await this.tester.testAuth0PolicySync(dto.policy);
    } catch (error: any) {
      this.logger.error(`Error testing Auth0 policy: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test Auth0 policy',
        { originalError: error.message },
      );
    }
  }

  async testAzureADConditionalAccess(dto: { policy: AzureADConditionalAccessPolicy }) {
    try {
      if (!dto.policy) {
        throw new ValidationException('Azure AD policy is required');
      }
      if (!dto.policy.id) {
        throw new ValidationException('Azure AD policy id is required');
      }
      return await this.tester.testAzureADConditionalAccess(dto.policy);
    } catch (error: any) {
      this.logger.error(`Error testing Azure AD conditional access: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test Azure AD conditional access',
        { originalError: error.message },
      );
    }
  }

  async testGCPIAMBinding(dto: { binding: GCPIAMBinding }) {
    try {
      if (!dto.binding) {
        throw new ValidationException('GCP IAM binding is required');
      }
      if (!dto.binding.resource) {
        throw new ValidationException('GCP IAM binding resource is required');
      }
      if (!dto.binding.role) {
        throw new ValidationException('GCP IAM binding role is required');
      }
      return await this.tester.testGCPIAMBindings(dto.binding);
    } catch (error: any) {
      this.logger.error(`Error testing GCP IAM binding: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test GCP IAM binding',
        { originalError: error.message },
      );
    }
  }

  async validatePolicySync(dto: {
    source: { type: string; config: any };
    target: { type: string; config: any };
  }) {
    try {
      if (!dto.source) {
        throw new ValidationException('Source configuration is required');
      }
      if (!dto.source.type) {
        throw new ValidationException('Source type is required');
      }
      if (!dto.target) {
        throw new ValidationException('Target configuration is required');
      }
      if (!dto.target.type) {
        throw new ValidationException('Target type is required');
      }
      const validTypes = ['ad', 'okta', 'auth0', 'azure-ad', 'gcp'];
      if (!validTypes.includes(dto.source.type)) {
        throw new ValidationException(
          `Invalid source type. Must be one of: ${validTypes.join(', ')}`,
        );
      }
      if (!validTypes.includes(dto.target.type)) {
        throw new ValidationException(
          `Invalid target type. Must be one of: ${validTypes.join(', ')}`,
        );
      }
      return await this.tester.validatePolicySynchronization(dto.source, dto.target);
    } catch (error: any) {
      this.logger.error(`Error validating policy sync: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate policy synchronization',
        { originalError: error.message },
      );
    }
  }

  private validateUser(user: User): void {
    if (!user) {
      throw new ValidationException('User is required');
    }
    if (!user.id) {
      throw new ValidationException('User id is required');
    }
  }
}

