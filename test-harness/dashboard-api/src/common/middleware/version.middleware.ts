import { Injectable, NestMiddleware, BadRequestException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class VersionMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Extract version from path or header
    const pathVersion = this.extractVersionFromPath(req.path);
    const headerVersion = req.headers['x-api-version'] as string;

    // Determine API version
    let apiVersion = pathVersion || headerVersion || 'v1'; // Default to v1

    // Normalize version format (remove 'v' prefix if present, then add it back)
    apiVersion = apiVersion.replace(/^v?/, 'v');

    // Validate version format
    if (!/^v\d+$/.test(apiVersion)) {
      throw new BadRequestException(`Invalid API version format: ${apiVersion}. Expected format: v1, v2, etc.`);
    }

    // Store version in request for use in controllers
    (req as any).apiVersion = apiVersion;

    // Add version to response headers
    res.setHeader('X-API-Version', apiVersion);

    // If version is deprecated, add warning header
    if (this.isDeprecated(apiVersion)) {
      res.setHeader('X-API-Deprecated', 'true');
      res.setHeader('Warning', `299 - "This API version (${apiVersion}) is deprecated. Please migrate to the latest version."`);
    }

    next();
  }

  private extractVersionFromPath(path: string): string | null {
    // Match /api/v1/... or /api/v2/... pattern
    const match = path.match(/^\/api\/(v\d+)\//);
    return match ? match[1] : null;
  }

  private isDeprecated(version: string): boolean {
    // Currently only v1 is supported, mark others as deprecated
    // In the future, you can add logic to mark older versions as deprecated
    const supportedVersions = ['v1'];
    return !supportedVersions.includes(version);
  }
}

