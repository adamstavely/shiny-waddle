<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show && dataset" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Database class="modal-title-icon" />
              <div>
                <h2>{{ dataset.name }}</h2>
                <p class="modal-subtitle">{{ dataset.type }} • {{ formatNumber(dataset.recordCount) }} records</p>
              </div>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="dataset-details">
              <div class="detail-section">
                <h3 class="section-title">Dataset Information</h3>
                <div class="detail-grid">
                  <div class="detail-item">
                    <span class="detail-label">Name:</span>
                    <span class="detail-value">{{ dataset.name }}</span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value" :class="`type-${dataset.type}`">
                      {{ dataset.type }}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Record Count:</span>
                    <span class="detail-value">{{ formatNumber(dataset.recordCount) }}</span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Health Status:</span>
                    <span class="detail-value" :class="`health-${dataset.healthStatus}`">
                      {{ dataset.healthStatus }}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Privacy Score:</span>
                    <span class="detail-value">{{ dataset.privacyScore || 'N/A' }}%</span>
                  </div>
                  <div class="detail-item" v-if="dataset.lastTested">
                    <span class="detail-label">Last Tested:</span>
                    <span class="detail-value">{{ formatDate(dataset.lastTested) }}</span>
                  </div>
                </div>
              </div>

              <div class="detail-section" v-if="dataset.piiFields && dataset.piiFields.length > 0">
                <h3 class="section-title">PII Fields ({{ dataset.piiFields.length }})</h3>
                <div class="pii-fields-list">
                  <span
                    v-for="field in dataset.piiFields"
                    :key="field"
                    class="pii-field-tag"
                  >
                    {{ field }}
                  </span>
                </div>
              </div>

              <div class="detail-section" v-if="dataset.schema">
                <h3 class="section-title">Schema</h3>
                <div class="schema-display">
                  <pre>{{ JSON.stringify(dataset.schema, null, 2) }}</pre>
                </div>
              </div>

              <div class="detail-section">
                <h3 class="section-title">Actions</h3>
                <div class="action-buttons">
                  <button @click="testDataset" class="btn-secondary">
                    <Play class="btn-icon" />
                    Run Health Test
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { Teleport } from 'vue';
import { Database, X, Play } from 'lucide-vue-next';

interface Props {
  show: boolean;
  dataset: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  test: [id: string];
}>();

function close() {
  emit('close');
}

function testDataset() {
  if (props.dataset) {
    emit('test', props.dataset.id);
  }
}

function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num);
}

function formatDate(date: Date): string {
  return new Date(date).toLocaleString();
}
</script>

<style scoped>
.large-modal {
  max-width: 800px;
}

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
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 4px;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.modal-subtitle {
  font-size: 0.875rem;
  color: #a0aec0;
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

.dataset-details {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.detail-section {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.75rem;
  color: #718096;
}

.detail-value {
  font-size: 0.9rem;
  color: #ffffff;
  font-weight: 500;
}

.type-raw {
  color: #fc8181;
}

.type-masked {
  color: #4facfe;
}

.type-synthetic {
  color: #22c55e;
}

.health-healthy {
  color: #22c55e;
}

.health-warning {
  color: #fbbf24;
}

.health-critical {
  color: #fc8181;
}

.pii-fields-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.pii-field-tag {
  padding: 6px 12px;
  background: rgba(251, 191, 36, 0.2);
  border-radius: 6px;
  color: #fbbf24;
  font-size: 0.875rem;
  font-weight: 500;
}

.schema-display {
  padding: 16px;
  background: rgba(15, 20, 25, 0.8);
  border-radius: 8px;
  overflow-x: auto;
}

.schema-display pre {
  margin: 0;
  color: #a0aec0;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.action-buttons {
  display: flex;
  gap: 12px;
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

