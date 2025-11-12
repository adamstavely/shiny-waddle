import { ContainerScanResult } from '../core/types';
export declare class ContainerSecurityScanner {
    scanImage(image: string): Promise<ContainerScanResult>;
    scanImages(images: string[]): Promise<ContainerScanResult[]>;
}
