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
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.exceptions-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.classification-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #4facfe;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 24px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: #a0aec0;
  font-size: 1rem;
}

.error-state {
  text-align: center;
  padding: 40px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 12px;
  margin-bottom: 24px;
}

.error-icon {
  width: 48px;
  height: 48px;
  color: #fc8181;
  margin: 0 auto 16px;
}

.error-state p {
  color: #fc8181;
  font-size: 1rem;
  margin-bottom: 16px;
}

.btn-retry {
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-retry:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.empty-state {
  text-align: center;
  padding: 60px 40px;
  color: #a0aec0;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.empty-state p {
  margin: 0 0 24px 0;
}

.exceptions-list,
.allowlists-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.exception-card,
.allowlist-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  transition: all 0.2s;
}

.exception-card:hover,
.allowlist-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
}

.exception-header,
.allowlist-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.exception-name,
.allowlist-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.exception-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.exception-status.status-pending {
  background: rgba(237, 137, 54, 0.1);
  color: #ed8936;
}

.exception-status.status-approved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.exception-status.status-rejected {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.allowlist-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.allowlist-status.enabled {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.allowlist-status.disabled {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
}

.exception-description,
.allowlist-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 8px 0;
}

.exception-meta {
  display: flex;
  gap: 16px;
  margin: 12px 0;
  font-size: 0.875rem;
  color: #718096;
}

.allowlist-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 12px 0;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
}

.detail-item {
  display: flex;
  gap: 8px;
}

.detail-label {
  font-weight: 500;
  color: #a0aec0;
  min-width: 80px;
}

.detail-value {
  color: #ffffff;
}

.exception-actions,
.allowlist-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}

.action-btn {
  padding: 6px 12px;
  border-radius: 6px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  background: rgba(15, 20, 25, 0.6);
  color: #ffffff;
  cursor: pointer;
  font-size: 0.875rem;
  display: flex;
  align-items: center;
  gap: 4px;
  transition: all 0.2s;
}

.action-btn:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(79, 172, 254, 0.1);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.enable-btn:hover {
  border-color: #22c55e;
  color: #22c55e;
}

.delete-btn:hover {
  border-color: #fc8181;
  color: #fc8181;
}

.disable-btn:hover {
  border-color: #ed8936;
  color: #ed8936;
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
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

.form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group input[type="checkbox"] {
  width: auto;
  margin-right: 8px;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
