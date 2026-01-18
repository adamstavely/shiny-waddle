import { PartialType } from '@nestjs/mapped-types';
import { CreateAlertChannelDto } from './create-alert-channel.dto';

export class UpdateAlertChannelDto extends PartialType(CreateAlertChannelDto) {}
