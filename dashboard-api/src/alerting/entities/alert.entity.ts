import { Alert, AggregatedAlert } from '../../../../services/alerting-engine';

export interface AlertEntity extends Alert {
  createdAt: Date;
  updatedAt?: Date;
}

export interface AggregatedAlertEntity extends AggregatedAlert {
  createdAt: Date;
  updatedAt?: Date;
}

export { Alert, AggregatedAlert };
