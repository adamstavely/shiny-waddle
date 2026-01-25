import { PartialType } from '@nestjs/mapped-types';
import { CreateTestDto } from './create-test.dto';
import { IsOptional, IsString } from 'class-validator';

export class UpdateTestDto extends PartialType(CreateTestDto) {
  @IsOptional()
  @IsString()
  changeReason?: string;
}

