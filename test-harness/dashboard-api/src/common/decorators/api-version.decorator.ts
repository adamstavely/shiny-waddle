import { SetMetadata } from '@nestjs/common';

export const API_VERSION_KEY = 'apiVersion';
export const ApiVersion = (version: string) => SetMetadata(API_VERSION_KEY, version);

