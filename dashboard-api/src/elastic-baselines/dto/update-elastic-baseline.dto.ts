import { PartialType } from '@nestjs/mapped-types';
import { CreateElasticBaselineDto } from './create-elastic-baseline.dto';

export class UpdateElasticBaselineDto extends PartialType(CreateElasticBaselineDto) {}
