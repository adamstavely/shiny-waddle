import { IsObject, IsNotEmpty } from 'class-validator';

export class CompareBaselineDto {
  @IsObject()
  @IsNotEmpty()
  currentConfig: Record<string, any>;
}
