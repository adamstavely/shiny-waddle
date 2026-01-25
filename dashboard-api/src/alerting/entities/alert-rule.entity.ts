import { AlertRule, AlertCondition } from '../../../../services/alerting-engine';

export interface AlertRuleEntity extends AlertRule {
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  updatedBy?: string;
}

export { AlertRule, AlertCondition };
