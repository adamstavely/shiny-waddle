import { Alert, AggregatedAlert } from '../../../../heimdall-framework/services/alerting-engine';

export interface AlertEntity extends Alert {
  createdAt: Date;
  updatedAt?: Date;
}

export interface AggregatedAlertEntity extends AggregatedAlert {
  createdAt: Date;
  updatedAt?: Date;
}

export { Alert, AggregatedAlert };
