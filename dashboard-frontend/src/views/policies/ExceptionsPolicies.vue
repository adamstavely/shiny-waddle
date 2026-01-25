<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Exceptions</h1>
          <p class="page-description">Manage policy exceptions and allowlists</p>
        </div>
      </div>
    </div>

    <div class="exceptions-content">
      <!-- Policy Exceptions Section -->
      <div class="classification-section">
        <div class="section-header">
          <h2 class="section-title">Policy Exceptions</h2>
          <button @click="openCreateExceptionModal" class="btn-primary">
            <Plus class="btn-icon" />
            Request Exception
          </button>
        </div>
        <div v-if="loadingExceptions" class="loading-state">
          <div class="loading-spinner"></div>
          <p>Loading exceptions...</p>
        </div>
        <div v-else-if="exceptionsError" class="error-state">
          <AlertTriangle class="error-icon" />
          <p>{{ exceptionsError }}</p>
          <button @click="loadExceptions" class="btn-retry">Retry</button>
        </div>
        <div v-else-if="exceptions.length === 0" class="empty-state">
          <AlertTriangle class="empty-icon" />
          <h3>No exceptions found</h3>
          <p>Policy exceptions will appear here when requested</p>
        </div>
        <div v-else class="exceptions-list">
          <div v-for="exception in exceptions" :key="exception.id" class="exception-card">
            <div class="exception-header">
              <h4 class="exception-name">{{ exception.name }}</h4>
              <span class="exception-status" :class="`status-${exception.status}`">{{ exception.status }}</span>
            </div>
            <p class="exception-description">{{ exception.description || exception.reason || 'No description' }}</p>
            <div class="exception-meta">
              <span>Requested by: {{ exception.requestedBy || 'Unknown' }}</span>
              <span>{{ formatDate(exception.requestedAt) }}</span>
            </div>
            <div class="exception-actions">
              <button v-if="exception.status === 'pending'" @click="approveException(exception.id)" class="action-btn enable-btn">
                Approve
              </button>
              <button @click="deleteException(exception.id)" class="action-btn delete-btn">
                <Trash2 class="action-icon" />
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Allowlists Section -->
      <div class="classification-section mt-xl">
        <div class="section-header">
          <h2 class="section-title">Allowlists</h2>
          <button @click="openCreateAllowlistModal" class="btn-primary">
            <Plus class="btn-icon" />
            Create Allowlist
          </button>
        </div>
        <div v-if="loadingAllowlists" class="loading-state">
          <div class="loading-spinner"></div>
          <p>Loading allowlists...</p>
        </div>
        <div v-else-if="allowlistsError" class="error-state">
          <AlertTriangle class="error-icon" />
          <p>{{ allowlistsError }}</p>
          <button @click="loadAllowlists" class="btn-retry">Retry</button>
        </div>
        <div v-else-if="allowlists.length === 0" class="empty-state">
          <AlertTriangle class="empty-icon" />
          <h3>No allowlists defined</h3>
          <p>Create your first allowlist to get started</p>
        </div>
        <div v-else class="allowlists-list">
          <div v-for="allowlist in allowlists" :key="allowlist.id" class="allowlist-card">
            <div class="allowlist-header">
              <h4 class="allowlist-name">{{ allowlist.name }}</h4>
              <span class="allowlist-status" :class="allowlist.enabled ? 'enabled' : 'disabled'">
                {{ allowlist.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <p class="allowlist-description">{{ allowlist.description || 'No description' }}</p>
            <div class="allowlist-details">
              <div class="detail-item">
                <span class="detail-label">Type:</span>
                <span class="detail-value">{{ allowlist.type }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Values:</span>
                <span class="detail-value">{{ Array.isArray(allowlist.values) ? allowlist.values.join(', ') : allowlist.values }}</span>
              </div>
            </div>
            <div class="allowlist-actions">
              <button @click="toggleAllowlist(allowlist)" class="action-btn" :class="allowlist.enabled ? 'disable-btn' : 'enable-btn'">
                {{ allowlist.enabled ? 'Disable' : 'Enable' }}
              </button>
              <button @click="deleteAllowlist(allowlist.id)" class="action-btn delete-btn">
                <Trash2 class="action-icon" />
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Exception Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateExceptionModal" class="modal-overlay" @click="closeExceptionModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <AlertTriangle class="modal-title-icon" />
                <h2>Request Exception</h2>
              </div>
              <button @click="closeExceptionModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveException" class="form">
                <div class="form-group">
                  <label>Exception Name</label>
                  <input v-model="exceptionForm.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Reason / Description</label>
                  <textarea v-model="exceptionForm.reason" rows="4" required></textarea>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeExceptionModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    Request Exception
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Create Allowlist Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateAllowlistModal" class="modal-overlay" @click="closeAllowlistModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <AlertTriangle class="modal-title-icon" />
                <h2>Create Allowlist</h2>
              </div>
              <button @click="closeAllowlistModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveAllowlist" class="form">
                <div class="form-group">
                  <label>Allowlist Name</label>
                  <input v-model="allowlistForm.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Description</label>
                  <textarea v-model="allowlistForm.description" rows="3"></textarea>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Type</label>
                    <Dropdown
                      v-model="allowlistForm.type"
                      :options="allowlistTypeOptions"
                      placeholder="Select type..."
                    />
                  </div>
                  <div class="form-group">
                    <label>
                      <input v-model="allowlistForm.enabled" type="checkbox" />
                      Enabled
                    </label>
                  </div>
                </div>
                <div class="form-group">
                  <label>Values (comma-separated)</label>
                  <textarea v-model="allowlistForm.valuesText" rows="4" placeholder="Enter values separated by commas"></textarea>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeAllowlistModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    Create Allowlist
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  AlertTriangle,
  Plus,
  Trash2,
  X
} from 'lucide-vue-next';
import Dropdown from '../../components/Dropdown.vue';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Exceptions' }
];

// Data
const exceptions = ref<any[]>([]);
const allowlists = ref<any[]>([]);
const loadingExceptions = ref(false);
const loadingAllowlists = ref(false);
const exceptionsError = ref<string | null>(null);
const allowlistsError = ref<string | null>(null);

// Modals
const showCreateExceptionModal = ref(false);
const showCreateAllowlistModal = ref(false);

// Forms
const exceptionForm = ref({
  name: '',
  reason: ''
});

const allowlistForm = ref({
  name: '',
  description: '',
  type: 'ip',
  enabled: true,
  valuesText: ''
});

const allowlistTypeOptions = [
  { label: 'IP Address', value: 'ip' },
  { label: 'Domain', value: 'domain' },
  { label: 'User', value: 'user' },
  { label: 'Resource', value: 'resource' }
];

const formatDate = (date: Date | string): string => {
  if (!date) return 'Unknown';
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - dateObj.getTime()) / (24 * 60 * 60 * 1000));
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  return dateObj.toLocaleDateString();
};

// API Calls
const loadExceptions = async () => {
  loadingExceptions.value = true;
  exceptionsError.value = null;
  try {
    const response = await axios.get('/api/v1/exceptions');
    exceptions.value = response.data || [];
  } catch (err: any) {
    exceptionsError.value = err.response?.data?.message || 'Failed to load exceptions';
    console.error('Error loading exceptions:', err);
  } finally {
    loadingExceptions.value = false;
  }
};

const loadAllowlists = async () => {
  loadingAllowlists.value = true;
  allowlistsError.value = null;
  try {
    const response = await axios.get('/api/v1/exceptions/allowlists');
    allowlists.value = response.data || [];
  } catch (err: any) {
    allowlistsError.value = err.response?.data?.message || 'Failed to load allowlists';
    console.error('Error loading allowlists:', err);
  } finally {
    loadingAllowlists.value = false;
  }
};

// Exception Actions
const openCreateExceptionModal = () => {
  exceptionForm.value = { name: '', reason: '' };
  showCreateExceptionModal.value = true;
};

const closeExceptionModal = () => {
  showCreateExceptionModal.value = false;
};

const saveException = async () => {
  try {
    await axios.post('/api/v1/exceptions', {
      name: exceptionForm.value.name,
      description: exceptionForm.value.reason,
      reason: exceptionForm.value.reason,
      status: 'pending'
    });
    await loadExceptions();
    closeExceptionModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to create exception');
    console.error('Error creating exception:', err);
  }
};

const approveException = async (id: string) => {
  try {
    await axios.post(`/api/v1/exceptions/${id}/approve`, { approver: 'current-user' });
    await loadExceptions();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to approve exception');
    console.error('Error approving exception:', err);
  }
};

const deleteException = async (id: string) => {
  if (confirm('Are you sure you want to delete this exception?')) {
    try {
      await axios.delete(`/api/v1/exceptions/${id}`);
      await loadExceptions();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete exception');
      console.error('Error deleting exception:', err);
    }
  }
};

// Allowlist Actions
const openCreateAllowlistModal = () => {
  allowlistForm.value = {
    name: '',
    description: '',
    type: 'ip',
    enabled: true,
    valuesText: ''
  };
  showCreateAllowlistModal.value = true;
};

const closeAllowlistModal = () => {
  showCreateAllowlistModal.value = false;
};

const saveAllowlist = async () => {
  try {
    const values = allowlistForm.value.valuesText
      .split(',')
      .map(v => v.trim())
      .filter(v => v.length > 0);
    
    await axios.post('/api/v1/exceptions/allowlists', {
      name: allowlistForm.value.name,
      description: allowlistForm.value.description,
      type: allowlistForm.value.type,
      enabled: allowlistForm.value.enabled,
      values: values
    });
    await loadAllowlists();
    closeAllowlistModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to create allowlist');
    console.error('Error creating allowlist:', err);
  }
};

const toggleAllowlist = async (allowlist: any) => {
  try {
    await axios.put(`/api/v1/exceptions/allowlists/${allowlist.id}`, {
      enabled: !allowlist.enabled
    });
    await loadAllowlists();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to toggle allowlist');
    console.error('Error toggling allowlist:', err);
  }
};

const deleteAllowlist = async (id: string) => {
  if (confirm('Are you sure you want to delete this allowlist?')) {
    try {
      await axios.delete(`/api/v1/exceptions/allowlists/${id}`);
      await loadAllowlists();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete allowlist');
      console.error('Error deleting allowlist:', err);
    }
  }
};

// Load data on mount
onMounted(() => {
  loadExceptions();
  loadAllowlists();
});
</script>

<style scoped>
.policies-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
  border: none;
  border-radius: var(--border-radius-lg);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.exceptions-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.classification-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.section-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-primary);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto var(--spacing-lg);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.error-state {
  text-align: center;
  padding: var(--spacing-2xl);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-lg);
  margin-bottom: var(--spacing-lg);
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
}

.error-state p {
  color: var(--color-error);
  font-size: var(--font-size-base);
  margin-bottom: var(--spacing-md);
}

.btn-retry {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-retry:hover {
  background: var(--border-color-primary);
  opacity: 0.2;
  border-color: var(--border-color-primary-active);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.empty-state p {
  margin: 0 0 var(--spacing-lg) 0;
}

.exceptions-list,
.allowlists-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.exception-card,
.allowlist-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  transition: var(--transition-all);
}

.exception-card:hover,
.allowlist-card:hover {
  border-color: var(--border-color-primary-hover);
}

.exception-header,
.allowlist-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.exception-name,
.allowlist-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.exception-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.exception-status.status-pending {
  background: var(--color-warning-bg);
  color: var(--color-warning-dark);
}

.exception-status.status-approved {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.exception-status.status-rejected {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.allowlist-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.allowlist-status.enabled {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.allowlist-status.disabled {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
}

.exception-description,
.allowlist-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin: var(--spacing-sm) 0;
}

.exception-meta {
  display: flex;
  gap: var(--spacing-md);
  margin: var(--spacing-sm) 0;
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.allowlist-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin: var(--spacing-sm) 0;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
}

.detail-item {
  display: flex;
  gap: var(--spacing-sm);
}

.detail-label {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
  min-width: 80px;
}

.detail-value {
  color: var(--color-text-primary);
}

.exception-actions,
.allowlist-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.action-btn {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  border: var(--border-width-thin) solid var(--border-color-primary);
  background: var(--color-bg-overlay-light);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  transition: var(--transition-all);
}

.action-btn:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--border-color-muted);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.enable-btn:hover {
  border-color: var(--color-success);
  color: var(--color-success);
}

.delete-btn:hover {
  border-color: var(--color-error);
  color: var(--color-error);
}

.disable-btn:hover {
  border-color: var(--color-warning-dark);
  color: var(--color-warning-dark);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-index-modal);
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.form-group input[type="checkbox"] {
  width: auto;
  margin-right: var(--spacing-sm);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
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
