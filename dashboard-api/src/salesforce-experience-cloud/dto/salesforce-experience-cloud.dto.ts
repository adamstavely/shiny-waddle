import { IsString, IsOptional, IsArray, IsBoolean, IsNumber, IsUrl } from 'class-validator';

export class CreateSalesforceExperienceCloudConfigDto {
  @IsString()
  name: string;

  @IsUrl()
  url: string;

  @IsOptional()
  @IsString()
  cookies?: string;

  @IsOptional()
  @IsString()
  outputDir?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  objectList?: string[];

  @IsOptional()
  @IsString()
  app?: string;

  @IsOptional()
  @IsString()
  aura?: string;

  @IsOptional()
  @IsString()
  context?: string;

  @IsOptional()
  @IsString()
  token?: string;

  @IsOptional()
  @IsBoolean()
  noGraphQL?: boolean;

  @IsOptional()
  @IsString()
  proxy?: string;

  @IsOptional()
  @IsBoolean()
  insecure?: boolean;

  @IsOptional()
  @IsString()
  auraRequestFile?: string;

  @IsOptional()
  @IsString()
  auraInspectorPath?: string;

  @IsOptional()
  @IsNumber()
  timeout?: number;

  @IsOptional()
  @IsString()
  pythonPath?: string;
}

export class UpdateSalesforceExperienceCloudConfigDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsUrl()
  url?: string;

  @IsOptional()
  @IsString()
  cookies?: string;

  @IsOptional()
  @IsString()
  outputDir?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  objectList?: string[];

  @IsOptional()
  @IsString()
  app?: string;

  @IsOptional()
  @IsString()
  aura?: string;

  @IsOptional()
  @IsString()
  context?: string;

  @IsOptional()
  @IsString()
  token?: string;

  @IsOptional()
  @IsBoolean()
  noGraphQL?: boolean;

  @IsOptional()
  @IsString()
  proxy?: string;

  @IsOptional()
  @IsBoolean()
  insecure?: boolean;

  @IsOptional()
  @IsString()
  auraRequestFile?: string;

  @IsOptional()
  @IsString()
  auraInspectorPath?: string;

  @IsOptional()
  @IsNumber()
  timeout?: number;

  @IsOptional()
  @IsString()
  pythonPath?: string;
}

export class RunGuestAccessTestDto {
  @IsString()
  configId: string;

  @IsOptional()
  @IsString()
  cookies?: string;
}

export class RunAuthenticatedAccessTestDto {
  @IsString()
  configId: string;

  @IsOptional()
  @IsString()
  cookies?: string;
}

export class RunGraphQLTestDto {
  @IsString()
  configId: string;
}

export class RunSelfRegistrationTestDto {
  @IsString()
  configId: string;
}

export class RunRecordListTestDto {
  @IsString()
  configId: string;
}

export class RunHomeURLTestDto {
  @IsString()
  configId: string;
}

export class RunObjectAccessTestDto {
  @IsString()
  configId: string;

  @IsArray()
  @IsString({ each: true })
  objects: string[];
}

export class RunFullAuditDto {
  @IsString()
  configId: string;
}
