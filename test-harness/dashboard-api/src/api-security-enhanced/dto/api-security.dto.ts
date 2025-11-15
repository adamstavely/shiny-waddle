import {
  IsNotEmpty,
  IsString,
  IsObject,
  IsArray,
  ValidateNested,
  IsOptional,
  IsIn,
  IsBoolean,
  IsNumber,
  IsDateString,
} from 'class-validator';
import { Type } from 'class-transformer';

export class AccessControlPolicyDto {
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  requiredRoles?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  requiredPermissions?: string[];

  @IsOptional()
  @IsObject()
  rateLimit?: {
    requests: number;
    window: number;
  };
}

export class APIVersioningTestDto {
  @IsNotEmpty()
  @IsString()
  version: string;

  @IsNotEmpty()
  @IsString()
  endpoint: string;

  @IsOptional()
  @IsBoolean()
  deprecated?: boolean;

  @IsOptional()
  @IsDateString()
  deprecationDate?: string;

  @IsOptional()
  @IsDateString()
  sunsetDate?: string;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => AccessControlPolicyDto)
  accessControl?: AccessControlPolicyDto;
}

export class GatewayPolicyConfigDto {
  @IsOptional()
  @IsString()
  method?: string;

  @IsOptional()
  @IsNumber()
  limit?: number;

  @IsOptional()
  @IsNumber()
  window?: number;

  @IsOptional()
  @IsString()
  policy?: string;

  @IsOptional()
  @IsBoolean()
  modifiesHeaders?: boolean;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  modifiedHeaders?: string[];

  @IsOptional()
  @IsString()
  type?: string;
}

export class GatewayPolicyDto {
  @IsNotEmpty()
  @IsString()
  id: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(['authentication', 'authorization', 'rate-limit', 'transformation', 'caching'])
  type: 'authentication' | 'authorization' | 'rate-limit' | 'transformation' | 'caching';

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => GatewayPolicyConfigDto)
  config?: GatewayPolicyConfigDto;
}

export class RouteDto {
  @IsNotEmpty()
  @IsString()
  path: string;

  @IsNotEmpty()
  @IsString()
  method: string;

  @IsNotEmpty()
  @IsString()
  target: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  policies?: string[];
}

export class GatewayPolicyValidationDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['aws-api-gateway', 'azure-api-management', 'kong', 'istio', 'envoy'])
  type: 'aws-api-gateway' | 'azure-api-management' | 'kong' | 'istio' | 'envoy';

  @IsNotEmpty()
  @IsString()
  endpoint: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => GatewayPolicyDto)
  policies?: GatewayPolicyDto[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RouteDto)
  routes?: RouteDto[];
}

export class WebhookAuthenticationDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['signature', 'token', 'oauth2'])
  type: 'signature' | 'token' | 'oauth2';

  @IsNotEmpty()
  @IsString()
  method: string;
}

export class WebhookEncryptionDto {
  @IsNotEmpty()
  @IsBoolean()
  enabled: boolean;

  @IsOptional()
  @IsString()
  method?: string;
}

export class WebhookRateLimitingDto {
  @IsNotEmpty()
  @IsNumber()
  maxRequests: number;

  @IsNotEmpty()
  @IsNumber()
  windowSeconds: number;
}

export class WebhookSecurityTestDto {
  @IsNotEmpty()
  @IsString()
  endpoint: string;

  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => WebhookAuthenticationDto)
  authentication: WebhookAuthenticationDto;

  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => WebhookEncryptionDto)
  encryption: WebhookEncryptionDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => WebhookRateLimitingDto)
  rateLimiting?: WebhookRateLimitingDto;
}

export class GraphQLSecurityTestDto {
  @IsNotEmpty()
  @IsString()
  endpoint: string;

  @IsNotEmpty()
  @IsString()
  schema: string;

  @IsOptional()
  @IsNumber()
  maxDepth?: number;

  @IsOptional()
  @IsNumber()
  maxComplexity?: number;

  @IsOptional()
  @IsBoolean()
  introspectionEnabled?: boolean;
}

export class ContractParameterDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(['query', 'header', 'path', 'body'])
  in: 'query' | 'header' | 'path' | 'body';

  @IsNotEmpty()
  @IsString()
  type: string;

  @IsNotEmpty()
  @IsBoolean()
  required: boolean;

  @IsOptional()
  @IsObject()
  schema?: any;
}

export class ContractResponseDto {
  @IsNotEmpty()
  @IsString()
  statusCode: string;

  @IsOptional()
  @IsObject()
  schema?: any;
}

export class ContractSecurityDto {
  @IsOptional()
  @IsString()
  type?: string;

  @IsOptional()
  @IsString()
  scheme?: string;
}

export class ContractEndpointDto {
  @IsNotEmpty()
  @IsString()
  path: string;

  @IsNotEmpty()
  @IsString()
  method: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ContractParameterDto)
  parameters?: ContractParameterDto[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ContractResponseDto)
  responses?: ContractResponseDto[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ContractSecurityDto)
  security?: ContractSecurityDto[];
}

export class ContractSecurityTestDto {
  @IsNotEmpty()
  @IsString()
  version: string;

  @IsNotEmpty()
  @IsObject()
  schema: any;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ContractEndpointDto)
  endpoints?: ContractEndpointDto[];
}

