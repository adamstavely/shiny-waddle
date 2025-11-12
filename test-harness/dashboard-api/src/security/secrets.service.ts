import { Injectable, NotFoundException } from '@nestjs/common';
import { EncryptionService } from './encryption.service';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface Secret {
  id: string;
  key: string;
  value: string; // Encrypted value
  description?: string;
  tags?: string[];
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  updatedBy?: string;
  metadata?: Record<string, any>;
}

export interface CreateSecretDto {
  key: string;
  value: string;
  description?: string;
  tags?: string[];
  createdBy?: string;
  metadata?: Record<string, any>;
}

export interface UpdateSecretDto {
  value?: string;
  description?: string;
  tags?: string[];
  updatedBy?: string;
  metadata?: Record<string, any>;
}

@Injectable()
export class SecretsService {
  private secrets: Map<string, Secret> = new Map();
  private readonly secretsFile: string;

  constructor(private readonly encryptionService: EncryptionService) {
    // Store secrets in a secure location
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
    this.secretsFile = path.join(dataDir, 'platform-secrets.json');
    this.loadSecrets();
  }

  /**
   * Load secrets from file
   */
  private async loadSecrets(): Promise<void> {
    try {
      const data = await fs.readFile(this.secretsFile, 'utf8');
      const secretsArray: Secret[] = JSON.parse(data);
      
      secretsArray.forEach(secret => {
        // Convert date strings back to Date objects
        secret.createdAt = new Date(secret.createdAt);
        secret.updatedAt = new Date(secret.updatedAt);
        this.secrets.set(secret.id, secret);
      });
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        // File doesn't exist yet, that's okay
        console.log('No existing secrets file found, starting fresh');
      } else {
        console.error('Error loading secrets:', error.message);
      }
    }
  }

  /**
   * Save secrets to file
   */
  private async saveSecrets(): Promise<void> {
    try {
      const secretsArray = Array.from(this.secrets.values());
      const dataDir = path.dirname(this.secretsFile);
      
      // Ensure directory exists
      await fs.mkdir(dataDir, { recursive: true });
      
      // Write to temporary file first, then rename (atomic operation)
      const tempFile = `${this.secretsFile}.tmp`;
      await fs.writeFile(tempFile, JSON.stringify(secretsArray, null, 2), 'utf8');
      await fs.rename(tempFile, this.secretsFile);
      
      // Set restrictive permissions (owner read/write only)
      await fs.chmod(this.secretsFile, 0o600);
    } catch (error: any) {
      console.error('Error saving secrets:', error.message);
      throw error;
    }
  }

  /**
   * Create a new secret
   */
  async createSecret(dto: CreateSecretDto): Promise<Secret> {
    // Check if key already exists
    const existing = Array.from(this.secrets.values()).find(s => s.key === dto.key);
    if (existing) {
      throw new Error(`Secret with key "${dto.key}" already exists`);
    }

    // Encrypt the value
    const encrypted = this.encryptionService.encryptAtRest(dto.value);
    const encryptedValue = JSON.stringify(encrypted);

    const secret: Secret = {
      id: uuidv4(),
      key: dto.key,
      value: encryptedValue,
      description: dto.description,
      tags: dto.tags || [],
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: dto.createdBy,
      metadata: dto.metadata,
    };

    this.secrets.set(secret.id, secret);
    await this.saveSecrets();

    return secret;
  }

  /**
   * Get a secret by ID (returns encrypted value)
   */
  async getSecretById(id: string): Promise<Secret> {
    const secret = this.secrets.get(id);
    if (!secret) {
      throw new NotFoundException(`Secret with ID "${id}" not found`);
    }
    return secret;
  }

  /**
   * Get a secret by key (returns decrypted value)
   */
  async getSecretByKey(key: string): Promise<{ id: string; key: string; value: string; description?: string; tags?: string[]; metadata?: Record<string, any> }> {
    const secret = Array.from(this.secrets.values()).find(s => s.key === key);
    if (!secret) {
      throw new NotFoundException(`Secret with key "${key}" not found`);
    }

    // Decrypt the value
    const encryptedData = JSON.parse(secret.value);
    const decryptedValue = this.encryptionService.decryptAtRest(encryptedData);

    return {
      id: secret.id,
      key: secret.key,
      value: decryptedValue,
      description: secret.description,
      tags: secret.tags,
      metadata: secret.metadata,
    };
  }

  /**
   * List all secrets (without values)
   */
  async listSecrets(tags?: string[]): Promise<Omit<Secret, 'value'>[]> {
    let secrets = Array.from(this.secrets.values());

    if (tags && tags.length > 0) {
      secrets = secrets.filter(s => 
        s.tags && tags.some(tag => s.tags!.includes(tag))
      );
    }

    return secrets.map(s => {
      const { value, ...rest } = s;
      return rest;
    });
  }

  /**
   * Update a secret
   */
  async updateSecret(id: string, dto: UpdateSecretDto): Promise<Secret> {
    const secret = this.secrets.get(id);
    if (!secret) {
      throw new NotFoundException(`Secret with ID "${id}" not found`);
    }

    // If value is being updated, encrypt it
    if (dto.value !== undefined) {
      const encrypted = this.encryptionService.encryptAtRest(dto.value);
      secret.value = JSON.stringify(encrypted);
    }

    if (dto.description !== undefined) {
      secret.description = dto.description;
    }

    if (dto.tags !== undefined) {
      secret.tags = dto.tags;
    }

    if (dto.updatedBy !== undefined) {
      secret.updatedBy = dto.updatedBy;
    }

    if (dto.metadata !== undefined) {
      secret.metadata = { ...secret.metadata, ...dto.metadata };
    }

    secret.updatedAt = new Date();
    this.secrets.set(id, secret);
    await this.saveSecrets();

    return secret;
  }

  /**
   * Delete a secret
   */
  async deleteSecret(id: string): Promise<void> {
    const secret = this.secrets.get(id);
    if (!secret) {
      throw new NotFoundException(`Secret with ID "${id}" not found`);
    }

    this.secrets.delete(id);
    await this.saveSecrets();
  }

  /**
   * Rotate a secret (create new version, keep old for migration period)
   */
  async rotateSecret(id: string, newValue: string, updatedBy?: string): Promise<Secret> {
    const secret = await this.getSecretById(id);
    
    // Store old value in metadata for migration
    const oldEncrypted = secret.value;
    if (!secret.metadata) {
      secret.metadata = {};
    }
    secret.metadata.previousValue = oldEncrypted;
    secret.metadata.rotatedAt = new Date().toISOString();

    // Encrypt new value
    const encrypted = this.encryptionService.encryptAtRest(newValue);
    secret.value = JSON.stringify(encrypted);
    secret.updatedAt = new Date();
    if (updatedBy) {
      secret.updatedBy = updatedBy;
    }

    this.secrets.set(id, secret);
    await this.saveSecrets();

    return secret;
  }
}

