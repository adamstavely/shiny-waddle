<template>
  <div class="evidence-manager">
    <div class="evidence-header">
      <h3>Evidence</h3>
      <button @click="showAddModal = true" class="btn-add-evidence">
        <Plus class="btn-icon" />
        Add Evidence
      </button>
    </div>

    <div v-if="evidence.length === 0" class="empty-state">
      <FileText class="empty-icon" />
      <p>No evidence added yet</p>
    </div>

    <div v-else class="evidence-list">
      <div
        v-for="item in evidence"
        :key="item.id"
        class="evidence-item"
      >
        <div class="evidence-icon" :class="`type-${item.type}`">
          <component :is="getEvidenceIcon(item.type)" class="icon" />
        </div>
        <div class="evidence-content">
          <div class="evidence-header-item">
            <h4 class="evidence-title">{{ item.title }}</h4>
            <div class="evidence-actions">
              <button @click="deleteEvidence(item.id)" class="action-btn delete-btn" title="Delete">
                <Trash2 class="action-icon" />
              </button>
            </div>
          </div>
          <p v-if="item.description" class="evidence-description">{{ item.description }}</p>
          <div class="evidence-meta">
            <span class="evidence-type">{{ formatType(item.type) }}</span>
            <span class="evidence-reference">
              <a v-if="isUrl(item.reference)" :href="item.reference" target="_blank" rel="noopener noreferrer" class="evidence-link">
                <ExternalLink class="link-icon" />
                {{ item.reference }}
              </a>
              <span v-else>{{ item.reference }}</span>
            </span>
            <span class="evidence-date">{{ formatDate(item.collectedAt) }}</span>
            <span class="evidence-collector">by {{ item.collectedBy }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Add Evidence Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddModal" class="modal-overlay" @click="closeAddModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Add Evidence</h2>
              <button @click="closeAddModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <form @submit.prevent="addEvidence" class="modal-body">
              <div class="form-group">
                <label>Type *</label>
                <select v-model="newEvidence.type" required>
                  <option value="policy">Policy</option>
                  <option value="test-result">Test Result</option>
                  <option value="documentation">Documentation</option>
                  <option value="configuration">Configuration</option>
                  <option value="audit-log">Audit Log</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div class="form-group">
                <label>Title *</label>
                <input v-model="newEvidence.title" type="text" required placeholder="Evidence title" />
              </div>
              <div class="form-group">
                <label>Description</label>
                <textarea v-model="newEvidence.description" rows="3" placeholder="Evidence description"></textarea>
              </div>
              <div class="form-group">
                <label>Reference *</label>
                <input v-model="newEvidence.reference" type="text" required placeholder="URL, file path, or ID" />
                <small>Enter a URL, file path, or reference ID</small>
              </div>
              <div class="form-actions">
                <button type="button" @click="closeAddModal" class="btn-secondary">Cancel</button>
                <button type="submit" class="btn-primary" :disabled="saving">
                  {{ saving ? 'Adding...' : 'Add Evidence' }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { Plus, Trash2, X, FileText, ExternalLink, Shield, FileCheck, Settings, FileSearch, Folder } from 'lucide-vue-next';

interface ComplianceEvidence {
  id: string;
  type: 'policy' | 'test-result' | 'documentation' | 'configuration' | 'audit-log' | 'other';
  title: string;
  description?: string;
  reference: string;
  collectedAt: Date | string;
  collectedBy: string;
}

interface Props {
  mappingId: string;
  evidence: ComplianceEvidence[];
}

const props = defineProps<Props>();
const emit = defineEmits<{
  'evidence-added': [evidence: ComplianceEvidence];
  'evidence-deleted': [evidenceId: string];
}>();

const showAddModal = ref(false);
const saving = ref(false);
const currentUser = ref('current-user@example.com'); // TODO: Get from auth context

const newEvidence = ref({
  type: 'policy' as ComplianceEvidence['type'],
  title: '',
  description: '',
  reference: '',
});

const getEvidenceIcon = (type: string) => {
  const icons: Record<string, any> = {
    'policy': Shield,
    'test-result': FileCheck,
    'documentation': FileText,
    'configuration': Settings,
    'audit-log': FileSearch,
    'other': Folder,
  };
  return icons[type] || FileText;
};

const formatType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

const isUrl = (str: string): boolean => {
  try {
    new URL(str);
    return true;
  } catch {
    return false;
  }
};

const closeAddModal = () => {
  showAddModal.value = false;
  newEvidence.value = {
    type: 'policy',
    title: '',
    description: '',
    reference: '',
  };
};

const addEvidence = async () => {
  if (!newEvidence.value.title || !newEvidence.value.reference) return;

  saving.value = true;
  try {
    const response = await fetch(`/api/compliance/mappings/${props.mappingId}/evidence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: newEvidence.value.type,
        title: newEvidence.value.title,
        description: newEvidence.value.description || undefined,
        reference: newEvidence.value.reference,
        collectedBy: currentUser.value,
      }),
    });

    if (response.ok) {
      const updatedMapping = await response.json();
      emit('evidence-added', updatedMapping.evidence[updatedMapping.evidence.length - 1]);
      closeAddModal();
    } else {
      const error = await response.json();
      alert(error.message || 'Failed to add evidence');
    }
  } catch (error) {
    console.error('Error adding evidence:', error);
    alert('Failed to add evidence');
  } finally {
    saving.value = false;
  }
};

const deleteEvidence = async (evidenceId: string) => {
  if (!confirm('Are you sure you want to delete this evidence?')) return;

  try {
    // Note: Backend may need DELETE endpoint for evidence
    // For now, we'll emit an event and let parent handle it
    emit('evidence-deleted', evidenceId);
    alert('Evidence deletion needs to be implemented in the backend');
  } catch (error) {
    console.error('Error deleting evidence:', error);
    alert('Failed to delete evidence');
  }
};
</script>

<style scoped>
.evidence-manager {
  margin-top: 24px;
}

.evidence-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.evidence-header h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-add-evidence {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-add-evidence:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 40px 20px;
  color: #718096;
}

.empty-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.evidence-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.evidence-item {
  display: flex;
  gap: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.evidence-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.evidence-icon .icon {
  width: 20px;
  height: 20px;
}

.type-policy {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.type-test-result {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.type-documentation {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.type-configuration {
  background: rgba(139, 92, 246, 0.2);
  color: #8b5cf6;
}

.type-audit-log {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.type-other {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.evidence-content {
  flex: 1;
}

.evidence-header-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.evidence-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.evidence-actions {
  display: flex;
  gap: 4px;
}

.action-btn {
  background: transparent;
  border: none;
  color: #718096;
  cursor: pointer;
  padding: 4px;
  border-radius: 4px;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.action-btn.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.evidence-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
  line-height: 1.5;
}

.evidence-meta {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  font-size: 0.75rem;
  color: #718096;
}

.evidence-type {
  font-weight: 600;
  text-transform: capitalize;
}

.evidence-reference {
  display: flex;
  align-items: center;
  gap: 4px;
}

.evidence-link {
  color: #4facfe;
  text-decoration: none;
  display: flex;
  align-items: center;
  gap: 4px;
}

.evidence-link:hover {
  text-decoration: underline;
}

.link-icon {
  width: 12px;
  height: 12px;
}

.evidence-date,
.evidence-collector {
  color: #718096;
}

/* Modal styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 24px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border-radius: 12px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  font-size: 1.5rem;
  margin: 0;
  color: #fff;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #fff;
}

.close-icon {
  width: 24px;
  height: 24px;
}

.modal-body {
  padding: 24px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 10px 12px;
  background: rgba(15, 20, 25, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.9rem;
  font-family: inherit;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
}

.form-group small {
  display: block;
  margin-top: 4px;
  font-size: 0.75rem;
  color: #718096;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-secondary {
  padding: 10px 20px;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.btn-primary {
  padding: 10px 20px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 6px;
  color: #ffffff;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

