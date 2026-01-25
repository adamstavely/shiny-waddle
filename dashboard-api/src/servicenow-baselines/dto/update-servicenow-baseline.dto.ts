import { PartialType } from '@nestjs/mapped-types';
import { CreateServiceNowBaselineDto } from './create-servicenow-baseline.dto';

export class UpdateServiceNowBaselineDto extends PartialType(CreateServiceNowBaselineDto) {}
