<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show && contract" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <FileText class="modal-title-icon" />
              <div>
                <h2>{{ contract.name }}</h2>
                <p class="modal-subtitle">{{ contract.dataOwner }} • v{{ contract.version }}</p>
              </div>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="contract-details">
              <div class="detail-section">
                <h3 class="section-title">Contract Information</h3>
                <div class="detail-grid">
                  <div class="detail-item">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value" :class="`status-${contract.status}`">
                      {{ contract.status }}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Machine Readable:</span>
                    <span class="detail-value" :class="contract.machineReadable ? 'value-success' : 'value-warning'">
                      {{ contract.machineReadable ? 'Yes' : 'No' }}
                    </span>
                  </div>
                  <div class="detail-item" v-if="contract.lastTested">
                    <span class="detail-label">Last Tested:</span>
                    <span class="detail-value">{{ formatDate(contract.lastTested) }}</span>
                  </div>
                </div>
              </div>

              <div class="detail-section" v-if="contract.requirements && contract.requirements.length > 0">
                <h3 class="section-title">Requirements ({{ contract.requirements.length }})</h3>
                <div class="requirements-list">
                  <div
                    v-for="req in contract.requirements"
                    :key="req.id"
                    class="requirement-item"
                  >
                    <div class="requirement-header">
                      <span class="req-type">{{ formatRequirementType(req.type) }}</span>
                      <span class="req-enforcement" :class="`enforcement-${req.enforcement}`">
                        {{ req.enforcement }}
                      </span>
                    </div>
                    <div class="req-description">{{ req.description }}</div>
                    <div class="req-rule">
                      <pre>{{ JSON.stringify(req.rule, null, 2) }}</pre>
                    </div>
                  </div>
                </div>
              </div>

              <div class="detail-section">
                <h3 class="section-title">Actions</h3>
                <div class="action-buttons">
                  <button @click="testContract" class="btn-secondary">
                    <Play class="btn-icon" />
                    Test Contract
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
import { FileText, X, Play } from 'lucide-vue-next';

interface Props {
  show: boolean;
  contract: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  test: [id: string];
}>();

function close() {
  emit('close');
}

function testContract() {
  if (props.contract) {
    emit('test', props.contract.id);
  }
}

function formatDate(date: Date): string {
  return new Date(date).toLocaleString();
}

function formatRequirementType(type: string): string {
  return type.split('-').map(word => 
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ');
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

.contract-details {
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

.status-active {
  color: #22c55e;
}

.status-draft {
  color: #fbbf24;
}

.status-deprecated {
  color: #fc8181;
}

.value-success {
  color: #22c55e;
}

.value-warning {
  color: #fbbf24;
}

.requirements-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.requirement-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  border-left: 3px solid #4facfe;
}

.requirement-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.req-type {
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
}

.req-enforcement {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}

.enforcement-hard {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.enforcement-soft {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.req-description {
  font-size: 0.9rem;
  color: #ffffff;
  margin-bottom: 12px;
  font-weight: 500;
}

.req-rule {
  padding: 12px;
  background: rgba(15, 20, 25, 0.8);
  border-radius: 6px;
}

.req-rule pre {
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

