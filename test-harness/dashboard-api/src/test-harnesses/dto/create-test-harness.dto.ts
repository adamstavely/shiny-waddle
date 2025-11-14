import {
  IsNotEmpty,
  IsString,
  IsOptional,
  IsArray,
} from 'class-validator';

export class CreateTestHarnessDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  testSuiteIds?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  applicationIds?: string[];

  @IsOptional()
  @IsString()
  team?: string;
}

