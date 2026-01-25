<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show && resource" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Database class="modal-title-icon" />
              <div>
                <h2>{{ resource.id }}</h2>
                <p class="modal-subtitle">{{ resource.type }}</p>
              </div>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="resource-details">
              <div class="detail-section">
                <h3 class="section-title">Basic Information</h3>
                <div class="detail-grid">
                  <div class="detail-item">
                    <span class="detail-label">Resource ID:</span>
                    <span class="detail-value">{{ resource.id }}</span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value">{{ resource.type }}</span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Sensitivity:</span>
                    <span class="detail-value" :class="`sensitivity-${resource.sensitivity}`">
                      {{ resource.sensitivity || 'N/A' }}
                    </span>
                  </div>
                  <div class="detail-item" v-if="resource.application">
                    <span class="detail-label">Application:</span>
                    <span class="detail-value">{{ resource.application }}</span>
                  </div>
                </div>
              </div>

              <div class="detail-section" v-if="resource.abacAttributes">
                <h3 class="section-title">ABAC Attributes</h3>
                <div class="attributes-grid">
                  <div
                    v-for="(value, key) in resource.abacAttributes"
                    :key="key"
                    class="attribute-item"
                  >
                    <span class="attr-key">{{ formatKey(key) }}:</span>
                    <span class="attr-value">{{ formatValue(value) }}</span>
                  </div>
                </div>
              </div>

              <div class="detail-section" v-if="resource.attributes">
                <h3 class="section-title">Additional Attributes</h3>
                <div class="attributes-grid">
                  <div
                    v-for="(value, key) in resource.attributes"
                    :key="key"
                    class="attribute-item"
                  >
                    <span class="attr-key">{{ formatKey(key) }}:</span>
                    <span class="attr-value">{{ formatValue(value) }}</span>
                  </div>
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
import { Database, X } from 'lucide-vue-next';

interface Props {
  show: boolean;
  resource: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
}>();

function close() {
  emit('close');
}

function formatKey(key: string): string {
  return key.split(/(?=[A-Z])/).map(word => 
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ');
}

function formatValue(value: any): string {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}
</script>

<style scoped>
.large-modal {
  max-width: 700px;
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

.resource-details {
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

.sensitivity-public {
  color: #22c55e;
}

.sensitivity-internal {
  color: #4facfe;
}

.sensitivity-confidential {
  color: #fbbf24;
}

.sensitivity-restricted {
  color: #fc8181;
}

.attributes-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.attribute-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.attr-key {
  font-size: 0.75rem;
  color: #718096;
  font-weight: 500;
}

.attr-value {
  font-size: 0.875rem;
  color: #ffffff;
  word-break: break-word;
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

