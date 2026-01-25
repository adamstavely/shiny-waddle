import { AlertChannel } from '../../../../heimdall-framework/services/alerting-engine';

export interface AlertChannelEntity extends AlertChannel {
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  updatedBy?: string;
}

export { AlertChannel };
