/**
 * Platform Connector Interface
 * 
 * Defines the interface for platform-specific connectors that fetch
 * configuration from external platforms (Salesforce, Elastic, etc.)
 */

export interface PlatformConnection {
  endpoint?: string;
  credentials?: Record<string, any>; // Encrypted credentials
}

export interface PlatformConnector {
  /**
   * Get current configuration from the platform
   */
  getConfiguration(connection: PlatformConnection): Promise<Record<string, any>>;

  /**
   * Test connection to platform
   */
  testConnection(connection: PlatformConnection): Promise<boolean>;
}
