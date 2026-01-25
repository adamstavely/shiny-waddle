import { IsString, IsBoolean, IsArray, IsOptional, IsEnum, ValidateNested, IsObject, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';
import { AlertCondition } from '../../../../heimdall-framework/services/alerting-engine';

export class AlertConditionDto implements AlertCondition {
  @IsString()
  field: string;

  @IsEnum(['equals', 'notEquals', 'greaterThan', 'lessThan', 'contains', 'matches', 'in'])
  operator: 'equals' | 'notEquals' | 'greaterThan' | 'lessThan' | 'contains' | 'matches' | 'in';

  @IsOptional()
  value: any;

  @IsOptional()
  @IsEnum(['AND', 'OR'])
  logicalOperator?: 'AND' | 'OR';
}

export class AggregationConfigDto {
  @IsBoolean()
  enabled: boolean;

  @IsNumber()
  window: number; // milliseconds

  @IsOptional()
  @IsNumber()
  maxAlerts?: number;
}

export class CreateAlertRuleDto {
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsBoolean()
  enabled: boolean;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AlertConditionDto)
  conditions: AlertConditionDto[];

  @IsArray()
  @IsString({ each: true })
  channels: string[]; // Channel IDs

  @IsOptional()
  @IsEnum(['critical', 'high', 'medium', 'low'])
  severity?: 'critical' | 'high' | 'medium' | 'low';

  @IsOptional()
  @ValidateNested()
  @Type(() => AggregationConfigDto)
  aggregation?: AggregationConfigDto;

  @IsOptional()
  @IsNumber()
  cooldown?: number; // milliseconds

  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
