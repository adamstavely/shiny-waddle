import { IsArray, IsString } from 'class-validator';

export class AssignTestConfigurationsDto {
  @IsArray()
  @IsString({ each: true })
  testConfigurationIds: string[];
}

