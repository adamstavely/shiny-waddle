import {
  IsOptional,
  IsString,
  IsArray,
} from 'class-validator';

export class UpdateTestHarnessDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

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

