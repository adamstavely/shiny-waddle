import { IsString, IsEnum, IsOptional, IsNotEmpty } from 'class-validator';

export class CreateMappingDto {
  @IsString()
  @IsNotEmpty()
  policyId: string;

  @IsString()
  @IsNotEmpty()
  controlId: string;

  @IsString()
  @IsNotEmpty()
  controlName: string;

  @IsEnum(['direct', 'partial', 'related'])
  mappingType: 'direct' | 'partial' | 'related';

  @IsString()
  @IsOptional()
  notes?: string;
}

