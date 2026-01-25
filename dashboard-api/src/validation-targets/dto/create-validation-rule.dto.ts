import { IsString, IsOptional, IsEnum, IsObject } from 'class-validator';

export enum RuleSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export class CreateValidationRuleDto {
  @IsString()
  name: string;

  @IsString()
  description: string;

  @IsString()
  targetId: string;

  @IsEnum(RuleSeverity)
  severity: RuleSeverity;

  @IsObject()
  ruleConfig: Record<string, any>;

  @IsOptional()
  @IsString()
  checkType?: string;

  @IsOptional()
  @IsObject()
  conditions?: Record<string, any>;
}

