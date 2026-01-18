<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Data Classification</h1>
          <p class="page-description">Manage data classification levels and rules</p>
        </div>
      </div>
    </div>

    <div class="data-classification-content">
      <!-- Classification Levels Section -->
      <div class="classification-section">
        <div class="section-header">
          <h2 class="section-title">Classification Levels</h2>
          <button @click="openCreateLevelModal" class="btn-primary">
            <Plus class="btn-icon" />
            Create Level
          </button>
        </div>
        <div v-if="loadingLevels" class="loading-state">
          <div class="loading-spinner"></div>
          <p>Loading levels...</p>
        </div>
        <div v-else-if="levelsError" class="error-state">
          <AlertTriangle class="error-icon" />
          <p>{{ levelsError }}</p>
          <button @click="loadLevels" class="btn-retry">Retry</button>
        </div>
        <div v-else-if="levels.length === 0" class="empty-state">
          <FileText class="empty-icon" />
          <h3>No classification levels defined</h3>
          <p>Create your first classification level to get started</p>
          <button @click="openCreateLevelModal" class="btn-primary">Create First Level</button>
        </div>
        <div v-else class="levels-grid">
          <div
            v-for="level in levels"
            :key="level.id"
            class="level-card"
            :style="{ borderLeftColor: level.color || '#4facfe' }"
          >
            <div class="level-header">
              <h3 class="level-name">{{ level.name }}</h3>
              <span class="level-sensitivity">{{ level.sensitivity }}</span>
            </div>
            <p class="level-description">{{ level.description }}</p>
            <div class="level-actions">
              <button @click="editLevel(level)" class="action-btn edit-btn">
                <Edit class="action-icon" />
                Edit
              </button>
              <button @click="deleteLevel(level.id)" class="action-btn delete-btn">
                <Trash2 class="action-icon" />
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Classification Rules Section -->
      <div class="classification-section mt-xl">
        <div class="section-header">
          <h2 class="section-title">Classification Rules</h2>
          <button @click="openCreateRuleModal" class="btn-primary">
            <Plus class="btn-icon" />
            Create Rule
          </button>
        </div>
        <div class="filters">
          <input
            v-model="ruleSearchQuery"
            type="text"
            placeholder="Search rules..."
            class="search-input"
          />
          <Dropdown
            v-model="ruleFilterLevel"
            :options="levelFilterOptions"
            placeholder="All Levels"
            class="filter-dropdown"
          />
          <Dropdown
            v-model="ruleFilterEnabled"
            :options="enabledFilterOptions"
            placeholder="All Statuses"
            class="filter-dropdown"
          />
        </div>
        <div v-if="loadingRules" class="loading-state">
          <div class="loading-spinner"></div>
          <p>Loading rules...</p>
        </div>
        <div v-else-if="rulesError" class="error-state">
          <AlertTriangle class="error-icon" />
          <p>{{ rulesError }}</p>
          <button @click="loadRules" class="btn-retry">Retry</button>
        </div>
        <div v-else-if="filteredRules.length === 0" class="empty-state">
          <FileText class="empty-icon" />
          <h3>No classification rules found</h3>
          <p>Create your first classification rule to get started</p>
          <button @click="openCreateRuleModal" class="btn-primary">Create First Rule</button>
        </div>
        <div v-else class="rules-list">
          <div
            v-for="rule in filteredRules"
            :key="rule.id"
            class="rule-card"
            :class="{ disabled: !rule.enabled }"
          >
            <div class="rule-header">
              <div class="rule-title-row">
                <h4 class="rule-name">{{ rule.name }}</h4>
                <span class="rule-status" :class="rule.enabled ? 'enabled' : 'disabled'">
                  {{ rule.enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </div>
              <p class="rule-description">{{ rule.description || 'No description' }}</p>
            </div>
            <div class="rule-details">
              <div class="rule-detail-item">
                <span class="detail-label">Level:</span>
                <span class="detail-value">{{ getLevelName(rule.levelId) }}</span>
              </div>
              <div class="rule-detail-item">
                <span class="detail-label">Condition:</span>
                <span class="detail-value">{{ rule.condition }} "{{ rule.value }}"</span>
              </div>
              <div v-if="rule.field" class="rule-detail-item">
                <span class="detail-label">Field:</span>
                <span class="detail-value">{{ rule.field }}</span>
              </div>
            </div>
            <div class="rule-actions">
              <button @click="editRule(rule)" class="action-btn edit-btn">
                <Edit class="action-icon" />
                Edit
              </button>
              <button @click="toggleRule(rule)" class="action-btn" :class="rule.enabled ? 'disable-btn' : 'enable-btn'">
                {{ rule.enabled ? 'Disable' : 'Enable' }}
              </button>
              <button @click="deleteRule(rule.id)" class="action-btn delete-btn">
                <Trash2 class="action-icon" />
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create/Edit Level Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateLevelModal" class="modal-overlay" @click="closeLevelModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <FileText class="modal-title-icon" />
                <h2>{{ editingLevel ? 'Edit Level' : 'Create Level' }}</h2>
              </div>
              <button @click="closeLevelModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveLevel" class="form">
                <div class="form-group">
                  <label>Level Name</label>
                  <input v-model="levelForm.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Description</label>
                  <textarea v-model="levelForm.description" rows="3" required></textarea>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Sensitivity</label>
                    <Dropdown
                      v-model="levelForm.sensitivity"
                      :options="sensitivityOptions"
                      placeholder="Select sensitivity..."
                    />
                  </div>
                  <div class="form-group">
                    <label>Color</label>
                    <div class="color-input-group">
                      <input v-model="levelForm.color" type="color" class="color-picker" />
                      <input v-model="levelForm.color" type="text" class="color-text" placeholder="#4facfe" />
                    </div>
                  </div>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeLevelModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    {{ editingLevel ? 'Update' : 'Create' }} Level
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Create/Edit Rule Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateRuleModal" class="modal-overlay" @click="closeRuleModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <FileText class="modal-title-icon" />
                <h2>{{ editingRule ? 'Edit Rule' : 'Create Rule' }}</h2>
              </div>
              <button @click="closeRuleModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveRule" class="form">
                <div class="form-group">
                  <label>Rule Name</label>
                  <input v-model="ruleForm.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Description</label>
                  <textarea v-model="ruleForm.description" rows="3"></textarea>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Classification Level</label>
                    <Dropdown
                      v-model="ruleForm.levelId"
                      :options="levelOptions"
                      placeholder="Select level..."
                    />
                  </div>
                  <div class="form-group">
                    <label>Condition</label>
                    <Dropdown
                      v-model="ruleForm.condition"
                      :options="conditionOptions"
                      placeholder="Select condition..."
                    />
                  </div>
                </div>
                <div class="form-group">
                  <label>Value</label>
                  <input v-model="ruleForm.value" type="text" required placeholder="Value to match" />
                </div>
                <div class="form-group">
                  <label>Field (Optional)</label>
                  <input v-model="ruleForm.field" type="text" placeholder="Field name to check" />
                </div>
                <div class="form-group">
                  <label>
                    <input v-model="ruleForm.enabled" type="checkbox" />
                    Enabled
                  </label>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeRuleModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    {{ editingRule ? 'Update' : 'Create' }} Rule
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
import { ref, computed, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  FileText,
  Plus,
  Edit,
  Trash2,
  AlertTriangle,
  X
} from 'lucide-vue-next';
import Dropdown from '../../components/Dropdown.vue';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Data Classification' }
];

// Data
const levels = ref<any[]>([]);
const rules = ref<any[]>([]);
const loadingLevels = ref(false);
const loadingRules = ref(false);
const levelsError = ref<string | null>(null);
const rulesError = ref<string | null>(null);

// Filters
const ruleSearchQuery = ref('');
const ruleFilterLevel = ref('');
const ruleFilterEnabled = ref('');

// Modals
const showCreateLevelModal = ref(false);
const showCreateRuleModal = ref(false);
const editingLevel = ref<any>(null);
const editingRule = ref<any>(null);

// Forms
const levelForm = ref({
  name: '',
  description: '',
  sensitivity: 'public' as 'public' | 'internal' | 'confidential' | 'restricted',
  color: '#4facfe'
});

const ruleForm = ref({
  name: '',
  description: '',
  levelId: '',
  condition: 'contains' as 'contains' | 'equals' | 'matches' | 'starts-with' | 'ends-with',
  value: '',
  field: '',
  enabled: true
});

// Options
const sensitivityOptions = [
  { label: 'Public', value: 'public' },
  { label: 'Internal', value: 'internal' },
  { label: 'Confidential', value: 'confidential' },
  { label: 'Restricted', value: 'restricted' }
];

const conditionOptions = [
  { label: 'Contains', value: 'contains' },
  { label: 'Equals', value: 'equals' },
  { label: 'Matches', value: 'matches' },
  { label: 'Starts With', value: 'starts-with' },
  { label: 'Ends With', value: 'ends-with' }
];

const levelFilterOptions = computed(() => [
  { label: 'All Levels', value: '' },
  ...levels.value.map(level => ({ label: level.name, value: level.id }))
]);

const levelOptions = computed(() =>
  levels.value.map(level => ({ label: level.name, value: level.id }))
);

const enabledFilterOptions = [
  { label: 'All Statuses', value: '' },
  { label: 'Enabled', value: 'true' },
  { label: 'Disabled', value: 'false' }
];

const filteredRules = computed(() => {
  let filtered = rules.value;
  if (ruleFilterLevel.value) {
    filtered = filtered.filter(r => r.levelId === ruleFilterLevel.value);
  }
  if (ruleFilterEnabled.value) {
    const enabled = ruleFilterEnabled.value === 'true';
    filtered = filtered.filter(r => r.enabled === enabled);
  }
  if (ruleSearchQuery.value) {
    const query = ruleSearchQuery.value.toLowerCase();
    filtered = filtered.filter(r =>
      r.name.toLowerCase().includes(query) ||
      r.description?.toLowerCase().includes(query) ||
      r.value.toLowerCase().includes(query)
    );
  }
  return filtered;
});

const getLevelName = (levelId: string): string => {
  const level = levels.value.find(l => l.id === levelId);
  return level?.name || 'Unknown';
};

// API Calls
const loadLevels = async () => {
  loadingLevels.value = true;
  levelsError.value = null;
  try {
    const response = await axios.get('/api/v1/data-classification/levels');
    levels.value = response.data || [];
  } catch (err: any) {
    levelsError.value = err.response?.data?.message || 'Failed to load classification levels';
    console.error('Error loading levels:', err);
  } finally {
    loadingLevels.value = false;
  }
};

const loadRules = async () => {
  loadingRules.value = true;
  rulesError.value = null;
  try {
    const response = await axios.get('/api/v1/data-classification/rules');
    rules.value = response.data || [];
  } catch (err: any) {
    rulesError.value = err.response?.data?.message || 'Failed to load classification rules';
    console.error('Error loading rules:', err);
  } finally {
    loadingRules.value = false;
  }
};

// Level Actions
const openCreateLevelModal = () => {
  editingLevel.value = null;
  levelForm.value = {
    name: '',
    description: '',
    sensitivity: 'public',
    color: '#4facfe'
  };
  showCreateLevelModal.value = true;
};

const editLevel = (level: any) => {
  editingLevel.value = level;
  levelForm.value = {
    name: level.name,
    description: level.description,
    sensitivity: level.sensitivity,
    color: level.color || '#4facfe'
  };
  showCreateLevelModal.value = true;
};

const closeLevelModal = () => {
  showCreateLevelModal.value = false;
  editingLevel.value = null;
};

const saveLevel = async () => {
  try {
    if (editingLevel.value) {
      await axios.put(`/api/v1/data-classification/levels/${editingLevel.value.id}`, levelForm.value);
    } else {
      await axios.post('/api/v1/data-classification/levels', levelForm.value);
    }
    await loadLevels();
    closeLevelModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to save level');
    console.error('Error saving level:', err);
  }
};

const deleteLevel = async (id: string) => {
  if (confirm('Are you sure you want to delete this classification level? This will also delete all associated rules.')) {
    try {
      await axios.delete(`/api/v1/data-classification/levels/${id}`);
      await loadLevels();
      await loadRules();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete level');
      console.error('Error deleting level:', err);
    }
  }
};

// Rule Actions
const openCreateRuleModal = () => {
  editingRule.value = null;
  ruleForm.value = {
    name: '',
    description: '',
    levelId: levels.value.length > 0 ? levels.value[0].id : '',
    condition: 'contains',
    value: '',
    field: '',
    enabled: true
  };
  showCreateRuleModal.value = true;
};

const editRule = (rule: any) => {
  editingRule.value = rule;
  ruleForm.value = {
    name: rule.name,
    description: rule.description || '',
    levelId: rule.levelId,
    condition: rule.condition,
    value: rule.value,
    field: rule.field || '',
    enabled: rule.enabled !== undefined ? rule.enabled : true
  };
  showCreateRuleModal.value = true;
};

const closeRuleModal = () => {
  showCreateRuleModal.value = false;
  editingRule.value = null;
};

const saveRule = async () => {
  try {
    if (editingRule.value) {
      await axios.put(`/api/v1/data-classification/rules/${editingRule.value.id}`, ruleForm.value);
    } else {
      await axios.post('/api/v1/data-classification/rules', ruleForm.value);
    }
    await loadRules();
    closeRuleModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to save rule');
    console.error('Error saving rule:', err);
  }
};

const toggleRule = async (rule: any) => {
  try {
    await axios.put(`/api/v1/data-classification/rules/${rule.id}`, {
      enabled: !rule.enabled
    });
    await loadRules();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to toggle rule');
    console.error('Error toggling rule:', err);
  }
};

const deleteRule = async (id: string) => {
  if (confirm('Are you sure you want to delete this classification rule?')) {
    try {
      await axios.delete(`/api/v1/data-classification/rules/${id}`);
      await loadRules();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete rule');
      console.error('Error deleting rule:', err);
    }
  }
};

// Load data on mount
onMounted(() => {
  loadLevels();
  loadRules();
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

.data-classification-content {
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

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  flex: 1;
  min-width: 200px;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.filter-dropdown {
  min-width: 150px;
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

.levels-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
}

.level-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-left: 4px solid;
  border-radius: 8px;
  padding: 16px;
  transition: all 0.2s;
}

.level-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.level-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.level-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.level-sensitivity {
  padding: 4px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  text-transform: uppercase;
}

.level-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 8px 0;
}

.level-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}

.rules-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.rule-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  transition: all 0.2s;
}

.rule-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
}

.rule-card.disabled {
  opacity: 0.6;
}

.rule-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.rule-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.rule-status {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.rule-status.enabled {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.rule-status.disabled {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
}

.rule-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 8px 0;
}

.rule-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 12px 0;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
}

.rule-detail-item {
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

.rule-actions {
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

.edit-btn:hover {
  border-color: #4facfe;
  color: #4facfe;
}

.delete-btn:hover {
  border-color: #fc8181;
  color: #fc8181;
}

.enable-btn:hover {
  border-color: #22c55e;
  color: #22c55e;
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

.color-input-group {
  display: flex;
  gap: 8px;
  align-items: center;
}

.color-picker {
  width: 60px;
  height: 40px;
  padding: 0;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
}

.color-text {
  flex: 1;
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
