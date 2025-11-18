import { IsString, IsEnum, IsOptional, IsNotEmpty, IsBoolean } from 'class-validator';

export class CreateClassificationRuleDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsNotEmpty()
  levelId: string;

  @IsString()
  @IsOptional()
  pattern?: string;

  @IsString()
  @IsOptional()
  field?: string;

  @IsEnum(['contains', 'equals', 'matches', 'starts-with', 'ends-with'])
  condition: 'contains' | 'equals' | 'matches' | 'starts-with' | 'ends-with';

  @IsString()
  @IsNotEmpty()
  value: string;

  @IsBoolean()
  @IsOptional()
  enabled?: boolean;
}

