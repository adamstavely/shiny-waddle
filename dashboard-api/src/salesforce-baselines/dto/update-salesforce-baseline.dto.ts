import { PartialType } from '@nestjs/mapped-types';
import { CreateSalesforceBaselineDto } from './create-salesforce-baseline.dto';

export class UpdateSalesforceBaselineDto extends PartialType(CreateSalesforceBaselineDto) {}
