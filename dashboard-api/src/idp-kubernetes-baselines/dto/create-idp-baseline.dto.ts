import { IsString, IsOptional, IsNotEmpty, IsObject, ValidateIf, IsBoolean, IsArray } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateIDPBaselineDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsNotEmpty()
  environment: string;

  @IsString()
  @IsOptional()
  version?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tags?: string[];

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;

  @Transform(({ value }) => {
    if (value === null || value === '') {
      return undefined;
    }
    return value;
  })
  @ValidateIf((o) => o.config !== undefined)
  @IsObject()
  config?: Record<string, any>;

  @IsString()
  @IsOptional()
  createdBy?: string;
}
