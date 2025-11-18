import { IsString, IsEnum, IsOptional, IsNotEmpty } from 'class-validator';

export class CreateClassificationLevelDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsEnum(['public', 'internal', 'confidential', 'restricted'])
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';

  @IsString()
  @IsOptional()
  color?: string;
}

