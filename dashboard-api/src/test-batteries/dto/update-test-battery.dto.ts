import {
  IsOptional,
  IsString,
  IsArray,
  IsObject,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { BatteryExecutionConfig } from '../../../../heimdall-framework/core/types';

class BatteryExecutionConfigDto implements BatteryExecutionConfig {
  @IsOptional()
  executionMode?: 'parallel' | 'sequential';

  @IsOptional()
  timeout?: number;

  @IsOptional()
  stopOnFailure?: boolean;
}

export class UpdateTestBatteryDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  harnessIds?: string[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => BatteryExecutionConfigDto)
  executionConfig?: BatteryExecutionConfig;

  @IsOptional()
  @IsString()
  team?: string;
}

