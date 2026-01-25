import { PartialType } from '@nestjs/mapped-types';
import { CreateIDPBaselineDto } from './create-idp-baseline.dto';

export class UpdateIDPBaselineDto extends PartialType(CreateIDPBaselineDto) {}
