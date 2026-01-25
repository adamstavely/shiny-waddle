import { Injectable, Optional, Inject } from '@nestjs/common';
import { AppLogger } from '../common/services/logger.service';
import * as crypto from 'crypto';

export interface EncryptionConfig {
  algorithm?: string;
  keyLength?: number;
  ivLength?: number;
}

export interface EncryptedData {
  encrypted: string;
  iv: string;
  tag?: string;
  algorithm: string;
}

@Injectable()
export class EncryptionService {
  private readonly algorithm: string;
  private readonly keyLength: number;
  private readonly ivLength: number;
  private encryptionKey: Buffer;
  private readonly logger = new AppLogger(EncryptionService.name);

  constructor(@Optional() @Inject('ENCRYPTION_CONFIG') config?: EncryptionConfig) {
    this.algorithm = config?.algorithm || 'aes-256-gcm';
    this.keyLength = config?.keyLength || 32; // 256 bits
    this.ivLength = config?.ivLength || 16; // 128 bits
    
    // Get encryption key from environment or generate one
    const keyFromEnv = process.env.ENCRYPTION_KEY;
    if (keyFromEnv) {
      // If provided as hex string, convert to buffer
      this.encryptionKey = Buffer.from(keyFromEnv, 'hex');
    } else {
      // Generate a key (in production, this should be stored securely)
      this.logger.warn('⚠️  WARNING: Using generated encryption key. Set ENCRYPTION_KEY environment variable for production.');
      this.encryptionKey = crypto.randomBytes(this.keyLength);
    }

    // Validate key length
    if (this.encryptionKey.length !== this.keyLength) {
      throw new Error(`Encryption key must be ${this.keyLength} bytes (${this.keyLength * 8} bits)`);
    }
  }

  /**
   * Encrypt data at rest
   */
  encryptAtRest(data: string | Buffer): EncryptedData {
    try {
      const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
      const iv = crypto.randomBytes(this.ivLength);
      
      const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
      
      let encrypted = cipher.update(dataBuffer);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      // For GCM mode, get authentication tag
      let tag: Buffer | undefined;
      if (this.algorithm.includes('gcm')) {
        tag = (cipher as crypto.CipherGCM).getAuthTag();
      }
      
      return {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag?.toString('base64'),
        algorithm: this.algorithm,
      };
    } catch (error: any) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data at rest
   */
  decryptAtRest(encryptedData: EncryptedData): string {
    try {
      const encrypted = Buffer.from(encryptedData.encrypted, 'base64');
      const iv = Buffer.from(encryptedData.iv, 'base64');
      
      const decipher = crypto.createDecipheriv(
        encryptedData.algorithm,
        this.encryptionKey,
        iv,
      );
      
      // Set authentication tag for GCM mode
      if (encryptedData.tag && encryptedData.algorithm.includes('gcm')) {
        (decipher as crypto.DecipherGCM).setAuthTag(Buffer.from(encryptedData.tag, 'base64'));
      }
      
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted.toString('utf8');
    } catch (error: any) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Encrypt data for transmission (returns base64 encoded string)
   */
  encryptInTransit(data: string | Buffer): string {
    const encrypted = this.encryptAtRest(data);
    // Return as JSON string for easy transmission
    return JSON.stringify(encrypted);
  }

  /**
   * Decrypt data received in transit
   */
  decryptInTransit(encryptedString: string): string {
    const encryptedData: EncryptedData = JSON.parse(encryptedString);
    return this.decryptAtRest(encryptedData);
  }

  /**
   * Hash data (one-way, for passwords, etc.)
   */
  hash(data: string, salt?: string): { hash: string; salt: string } {
    const actualSalt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto
      .pbkdf2Sync(data, actualSalt, 10000, 64, 'sha512')
      .toString('hex');
    
    return { hash, salt: actualSalt };
  }

  /**
   * Verify hashed data
   */
  verifyHash(data: string, hash: string, salt: string): boolean {
    const computedHash = crypto
      .pbkdf2Sync(data, salt, 10000, 64, 'sha512')
      .toString('hex');
    
    return computedHash === hash;
  }

  /**
   * Generate a secure random token
   */
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate a secure random password
   */
  generateSecurePassword(length: number = 16): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    const randomBytes = crypto.randomBytes(length);
    let password = '';
    
    for (let i = 0; i < length; i++) {
      password += charset[randomBytes[i] % charset.length];
    }
    
    return password;
  }
}


