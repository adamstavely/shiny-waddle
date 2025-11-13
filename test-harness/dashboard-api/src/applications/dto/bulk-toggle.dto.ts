import { IsArray, IsBoolean, IsOptional, IsString, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class BulkToggleItemDto {
  @IsString()
  id: string;

  @IsBoolean()
  enabled: boolean;

  @IsString()
  @IsOptional()
  reason?: string;
}

export class BulkToggleDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => BulkToggleItemDto)
  items: BulkToggleItemDto[];
}

