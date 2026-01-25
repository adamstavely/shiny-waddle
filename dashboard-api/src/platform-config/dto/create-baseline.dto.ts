import { IsString, IsOptional, IsNotEmpty, IsObject, ValidateIf } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateBaselineDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsNotEmpty()
  environment: string;

  @Transform(({ value }) => {
    // Convert null, empty string, or missing value to undefined
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

