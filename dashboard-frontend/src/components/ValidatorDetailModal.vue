<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Shield class="modal-title-icon" />
              <h2>Validator Details</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body" v-if="validator">
            <div class="detail-section">
              <h3 class="section-title">Basic Information</h3>
              <div class="info-grid">
                <div class="info-item">
                  <span class="info-label">Name</span>
                  <span class="info-value">{{ validator.name }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">ID</span>
                  <span class="info-value">{{ validator.id }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Version</span>
                  <span class="info-value">{{ validator.version }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Test Type</span>
                  <span class="info-value">{{ validator.testType }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Status</span>
                  <span class="info-value" :class="validator.enabled ? 'status-enabled' : 'status-disabled'">
                    {{ validator.enabled ? 'Enabled' : 'Disabled' }}
                  </span>
                </div>
                <div class="info-item">
                  <span class="info-label">Registered</span>
                  <span class="info-value">{{ formatDate(validator.registeredAt) }}</span>
                </div>
              </div>
            </div>

            <div class="detail-section">
              <h3 class="section-title">Description</h3>
              <p class="description-text">{{ validator.description }}</p>
            </div>

            <div class="detail-section" v-if="validator.metadata">
              <h3 class="section-title">Metadata</h3>
              <div class="metadata-content">
                <div v-if="validator.metadata.supportedTestTypes && validator.metadata.supportedTestTypes.length > 0" class="metadata-item">
                  <span class="metadata-label">Supported Test Types:</span>
                  <div class="metadata-values">
                    <span v-for="type in validator.metadata.supportedTestTypes" :key="type" class="badge">
                      {{ type }}
                    </span>
                  </div>
                </div>
                <div v-if="validator.metadata.requiredConfig && validator.metadata.requiredConfig.length > 0" class="metadata-item">
                  <span class="metadata-label">Required Config:</span>
                  <div class="metadata-values">
                    <span v-for="key in validator.metadata.requiredConfig" :key="key" class="badge">
                      {{ key }}
                    </span>
                  </div>
                </div>
                <div v-if="validator.metadata.dependencies && validator.metadata.dependencies.length > 0" class="metadata-item">
                  <span class="metadata-label">Dependencies:</span>
                  <div class="metadata-values">
                    <span v-for="dep in validator.metadata.dependencies" :key="dep" class="badge">
                      {{ dep }}
                    </span>
                  </div>
                </div>
                <div v-if="validator.metadata.tags && validator.metadata.tags.length > 0" class="metadata-item">
                  <span class="metadata-label">Tags:</span>
                  <div class="metadata-values">
                    <span v-for="tag in validator.metadata.tags" :key="tag" class="badge">
                      {{ tag }}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div class="detail-section" v-if="validator.metadata?.exampleConfig">
              <h3 class="section-title">Example Configuration</h3>
              <pre class="config-preview">{{ JSON.stringify(validator.metadata.exampleConfig, null, 2) }}</pre>
            </div>

            <div class="detail-section" v-if="validator.config && Object.keys(validator.config).length > 0">
              <h3 class="section-title">Current Configuration</h3>
              <pre class="config-preview">{{ maskSensitiveData(validator.config) }}</pre>
            </div>

            <div class="detail-section">
              <h3 class="section-title">Statistics</h3>
              <div class="stats-grid">
                <div class="stat-item">
                  <span class="stat-label">Tests Executed</span>
                  <span class="stat-value">{{ validator.testCount || 0 }}</span>
                </div>
                <div class="stat-item">
                  <span class="stat-label">Success Count</span>
                  <span class="stat-value success">{{ validator.successCount || 0 }}</span>
                </div>
                <div class="stat-item">
                  <span class="stat-label">Failure Count</span>
                  <span class="stat-value failure">{{ validator.failureCount || 0 }}</span>
                </div>
                <div class="stat-item">
                  <span class="stat-label">Success Rate</span>
                  <span class="stat-value" :class="getSuccessRateClass(validator)">
                    {{ getSuccessRate(validator) }}%
                  </span>
                </div>
                <div class="stat-item" v-if="validator.lastRunAt">
                  <span class="stat-label">Last Run</span>
                  <span class="stat-value">{{ formatDate(validator.lastRunAt) }}</span>
                </div>
              </div>
            </div>

            <div class="modal-actions">
              <button @click="$emit('edit', validator)" class="btn-secondary">
                <Edit class="btn-icon" />
                Edit
              </button>
              <button
                @click="$emit('toggle', validator)"
                class="btn-secondary"
                :class="validator.enabled ? 'disable-btn' : 'enable-btn'"
              >
                <component :is="validator.enabled ? PowerOff : Power" class="btn-icon" />
                {{ validator.enabled ? 'Disable' : 'Enable' }}
              </button>
              <button @click="$emit('test', validator)" class="btn-primary">
                <TestTube class="btn-icon" />
                Test Connection
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { Shield, X, Edit, Power, PowerOff, TestTube } from 'lucide-vue-next';
import { Teleport } from 'vue';

interface Validator {
  id: string;
  name: string;
  description: string;
  testType: string;
  version: string;
  enabled: boolean;
  testCount?: number;
  successCount?: number;
  failureCount?: number;
  lastRunAt?: Date | string;
  registeredAt: Date | string;
  config?: Record<string, any>;
  metadata?: {
    supportedTestTypes?: string[];
    requiredConfig?: string[];
    optionalConfig?: string[];
    dependencies?: string[];
    tags?: string[];
    exampleConfig?: any;
  };
}

defineProps<{
  show: boolean;
  validator: Validator | null;
}>();

defineEmits<{
  close: [];
  edit: [validator: Validator];
  toggle: [validator: Validator];
  test: [validator: Validator];
}>();

const getSuccessRate = (validator: Validator): number => {
  if (!validator.testCount || validator.testCount === 0) return 0;
  const success = validator.successCount || 0;
  return Math.round((success / validator.testCount) * 100);
};

const getSuccessRateClass = (validator: Validator): string => {
  const rate = getSuccessRate(validator);
  if (rate >= 90) return 'rate-high';
  if (rate >= 70) return 'rate-medium';
  return 'rate-low';
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

const maskSensitiveData = (config: Record<string, any>): string => {
  const sensitiveKeys = ['password', 'secret', 'key', 'token', 'apiKey', 'apikey', 'auth'];
  const masked = { ...config };
  
  const maskValue = (obj: any): any => {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(maskValue);
    
    const result: any = {};
    for (const [key, value] of Object.entries(obj)) {
      if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk.toLowerCase()))) {
        result[key] = '***MASKED***';
      } else if (typeof value === 'object') {
        result[key] = maskValue(value);
      } else {
        result[key] = value;
      }
    }
    return result;
  };
  
  return JSON.stringify(maskValue(masked), null, 2);
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.detail-section {
  margin-bottom: 32px;
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.info-value {
  font-size: 0.9rem;
  color: #ffffff;
  font-weight: 500;
}

.status-enabled {
  color: #22c55e;
}

.status-disabled {
  color: #9ca3af;
}

.description-text {
  font-size: 0.9rem;
  color: #a0aec0;
  line-height: 1.6;
  margin: 0;
}

.metadata-content {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.metadata-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.metadata-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.metadata-values {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.badge {
  padding: 4px 10px;
  border-radius: 6px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.config-preview {
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #a0aec0;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  overflow-x: auto;
  margin: 0;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
}

.stat-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.stat-label {
  font-size: 0.875rem;
  color: #718096;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.stat-value.success {
  color: #22c55e;
}

.stat-value.failure {
  color: #fc8181;
}

.rate-high {
  color: #22c55e;
}

.rate-medium {
  color: #fbbf24;
}

.rate-low {
  color: #fc8181;
}

.modal-actions {
  display: flex;
  gap: 12px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.enable-btn:hover {
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.disable-btn:hover {
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

