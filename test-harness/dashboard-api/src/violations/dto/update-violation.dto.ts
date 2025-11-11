import { ViolationStatus } from './create-violation.dto';

export interface UpdateViolationDto {
  status?: ViolationStatus;
  assignedTo?: string | null;
  title?: string;
  description?: string;
  remediationStatus?: string;
  resolvedAt?: Date;
  resolvedBy?: string;
  ignoredAt?: Date;
  ignoredBy?: string;
  relatedViolationIds?: string[];
}

