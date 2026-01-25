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

.data-classification-content {
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

.filters {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
  flex-wrap: wrap;
}

.search-input {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  flex: 1;
  min-width: 200px;
}

.search-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.filter-dropdown {
  min-width: 150px;
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

.levels-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: var(--spacing-md);
}

.level-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left: 4px solid;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  transition: var(--transition-all);
}

.level-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.level-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.level-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.level-sensitivity {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  text-transform: uppercase;
}

.level-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin: var(--spacing-sm) 0;
}

.level-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: 12px;
}

.rules-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.rule-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  transition: var(--transition-all);
}

.rule-card:hover {
  border-color: var(--border-color-primary-hover);
}

.rule-card.disabled {
  opacity: var(--opacity-disabled);
}

.rule-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.rule-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.rule-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.rule-status.enabled {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.rule-status.disabled {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
}

.rule-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin: var(--spacing-sm) 0;
}

.rule-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin: var(--spacing-sm) 0;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-dark);
  opacity: 0.4;
  border-radius: var(--border-radius-sm);
}

.rule-detail-item {
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

.rule-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: 12px;
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

.edit-btn:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.delete-btn:hover {
  border-color: var(--color-error);
  color: var(--color-error);
}

.enable-btn:hover {
  border-color: var(--color-success);
  color: var(--color-success);
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
  gap: var(--spacing-lg);
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

.color-input-group {
  display: flex;
  gap: var(--spacing-sm);
  align-items: center;
}

.color-picker {
  width: 60px;
  height: 40px;
  padding: 0;
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  cursor: pointer;
}

.color-text {
  flex: 1;
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
  margin-top: 8px;
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
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
