import { Policy } from '../../entities/policy.entity';

export class ValidatePolicyDto {
  policy?: Policy;
  json?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
}

export interface ValidationError {
  field: string;
  message: string;
  severity: 'error' | 'warning';
  code?: string;
}
