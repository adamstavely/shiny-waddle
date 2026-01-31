<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Access Control Policies</h1>
          <p class="page-description">Manage RBAC and ABAC access control policies</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Policy
        </button>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search policies..."
        class="search-input"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
    </div>

    <!-- Loading State -->
    <div v-if="loading && policies.length === 0" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading policies...</p>
    </div>

    <!-- Error State -->
    <div v-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadPolicies" class="btn-retry">Retry</button>
    </div>

    <!-- Policies Grid -->
    <div v-if="!loading || policies.length > 0" class="policies-grid">
      <div
        v-for="policy in filteredPolicies"
        :key="policy.id"
        class="policy-card"
        @click="viewPolicy(policy.id)"
      >
        <div class="policy-header">
          <div class="policy-title-row">
            <h3 class="policy-name">{{ policy.name }}</h3>
            <span class="policy-status" :class="`status-${policy.status}`">
              {{ policy.status }}
            </span>
          </div>
          <p class="policy-meta">
            {{ policy.type.toUpperCase() }} • v{{ policy.version }}
          </p>
        </div>

        <p class="policy-description">{{ policy.description }}</p>

        <div class="policy-stats">
          <div class="stat">
            <span class="stat-label">Rules</span>
            <span class="stat-value">{{ policy.ruleCount }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">Tests</span>
            <span class="stat-value">{{ getTestCount(policy.id) }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">Last Updated</span>
            <span class="stat-value">{{ formatDate(policy.lastUpdated) }}</span>
          </div>
        </div>

        <div class="policy-actions">
          <button @click.stop="editPolicy(policy.id)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click.stop="viewVersions(policy.id)" class="action-btn view-btn">
            <History class="action-icon" />
            Versions
          </button>
          <button @click.stop="compareVersions(policy.id)" class="action-btn view-btn">
            <GitCompare class="action-icon" />
            Compare
          </button>
          <button @click.stop="viewGapAnalysis(policy.id)" class="action-btn view-btn">
            <AlertTriangle class="action-icon" />
            View Gaps
          </button>
          <button @click.stop="viewSystemState(policy.id)" class="action-btn view-btn">
            <Shield class="action-icon" />
            Compare State
          </button>
          <button @click.stop="testPolicy(policy.id)" class="action-btn test-btn">
            <TestTube class="action-icon" />
            Test
          </button>
          <button @click.stop="viewTestsUsingPolicy(policy.id)" class="action-btn view-btn" v-if="getTestCount(policy.id) > 0">
            <TestTube class="action-icon" />
            View Tests ({{ getTestCount(policy.id) }})
          </button>
          <button @click.stop="deletePolicy(policy.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredPolicies.length === 0 && !loading" class="empty-state">
      <Shield class="empty-icon" />
      <h3>No policies found</h3>
      <p>Create your first policy to get started</p>
      <button @click="showCreateModal = true" class="btn-primary">
        Create Policy
      </button>
    </div>

    <!-- Create/Edit Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal || editingPolicy" class="modal-overlay" @click="closeModal">
          <div class="modal-content policy-editor" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Shield class="modal-title-icon" />
                <h2>{{ editingPolicy ? 'Edit Policy' : 'Create Policy' }}</h2>
              </div>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="savePolicy" class="policy-form">
                <!-- Editor Tabs -->
                <div class="editor-tabs">
                  <button
                    type="button"
                    @click="editorTab = 'basic'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'basic' }"
                  >
                    Basic Info
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'rules'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'rules' }"
                  >
                    {{ policyForm.type === 'rbac' ? 'Rules' : 'Conditions' }}
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'visual'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'visual' }"
                  >
                    Visual Builder
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'code'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'code' }"
                  >
                    Code
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'preview'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'preview' }"
                  >
                    Preview
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'versions'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'versions' }"
                    v-if="editingPolicy"
                  >
                    Versions
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'comparison'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'comparison' }"
                    v-if="editingPolicy"
                  >
                    System State
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'gaps'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'gaps' }"
                    v-if="editingPolicy"
                  >
                    Gap Analysis
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'tags'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'tags' }"
                    v-if="editingPolicy"
                  >
                    Tags
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'comments'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'comments' }"
                    v-if="editingPolicy"
                  >
                    Comments
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'approvals'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'approvals' }"
                    v-if="editingPolicy"
                  >
                    Approvals
                  </button>
                </div>

                <!-- Basic Info Tab -->
                <div v-if="editorTab === 'basic'" class="editor-content">
                  <div class="form-group">
                    <label>Policy Name</label>
                    <input v-model="policyForm.name" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Description</label>
                    <textarea v-model="policyForm.description" rows="3"></textarea>
                  </div>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Policy Type</label>
                      <Dropdown
                        v-model="policyForm.type"
                        :options="policyTypeOptions"
                        placeholder="Select type..."
                      />
                    </div>
                    <div class="form-group">
                      <label>Version</label>
                      <input v-model="policyForm.version" type="text" required />
                    </div>
                  </div>
                  <div v-if="policyForm.type === 'abac'" class="form-row">
                    <div class="form-group">
                      <label>Effect</label>
                      <Dropdown
                        v-model="policyForm.effect"
                        :options="effectOptions"
                        placeholder="Select effect..."
                      />
                    </div>
                    <div class="form-group">
                      <label>Priority</label>
                      <input v-model.number="policyForm.priority" type="number" min="0" />
                      <small>Higher priority policies are evaluated first</small>
                    </div>
                  </div>
                  <div class="form-group">
                    <label>Status</label>
                    <Dropdown
                      v-model="policyForm.status"
                      :options="policyStatusOptions"
                      placeholder="Select status..."
                    />
                  </div>
                </div>

                <!-- Rules/Conditions Tab -->
                <div v-if="editorTab === 'rules'" class="editor-content">
                  <!-- RBAC Rules -->
                  <div v-if="policyForm.type === 'rbac'">
                    <div class="section-header">
                      <h3>Policy Rules</h3>
                      <button type="button" @click="addRBACRule" class="btn-add">
                        <Plus class="btn-icon" />
                        Add Rule
                      </button>
                    </div>
                    <div class="rules-list">
                      <div
                        v-for="(rule, index) in policyForm.rules"
                        :key="index"
                        class="rule-card"
                      >
                        <div class="rule-header">
                          <h4>Rule {{ index + 1 }}</h4>
                          <button
                            type="button"
                            @click="removeRule(index)"
                            class="btn-remove"
                          >
                            <Trash2 class="icon" />
                          </button>
                        </div>
                        <div class="form-group">
                          <label>Rule ID</label>
                          <input
                            v-model="rule.id"
                            type="text"
                            placeholder="e.g., admin-full-access"
                            required
                          />
                        </div>
                        <div class="form-group">
                          <label>Description</label>
                          <textarea
                            v-model="rule.description"
                            rows="2"
                            placeholder="Describe what this rule does"
                          ></textarea>
                        </div>
                        <div class="form-group">
                          <label>Effect</label>
                          <Dropdown
                            v-model="rule.effect"
                            :options="effectOptions"
                            placeholder="Select effect..."
                          />
                        </div>
                        <div class="form-group">
                          <label>Conditions</label>
                          <div class="conditions-list">
                            <div
                              v-for="(value, key, condIndex) in rule.conditions"
                              :key="condIndex"
                              class="condition-item"
                            >
                              <input
                                v-model="conditionKeys[index][condIndex]"
                                type="text"
                                placeholder="e.g., subject.role"
                                class="condition-key"
                                @input="updateConditionKey(index, condIndex, $event)"
                              />
                              <span class="condition-separator">:</span>
                              <input
                                v-model="conditionValues[index][condIndex]"
                                type="text"
                                placeholder="e.g., admin or [admin, viewer]"
                                class="condition-value"
                                @input="updateConditionValue(index, condIndex, $event)"
                              />
                              <button
                                type="button"
                                @click="removeCondition(index, condIndex)"
                                class="btn-remove-small"
                              >
                                <X class="icon" />
                              </button>
                            </div>
                            <button
                              type="button"
                              @click="addCondition(index)"
                              class="btn-add-condition"
                            >
                              <Plus class="icon" />
                              Add Condition
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- ABAC Conditions -->
                  <div v-if="policyForm.type === 'abac'">
                    <div class="section-header">
                      <h3>Policy Conditions</h3>
                      <button type="button" @click="addABACCondition" class="btn-add">
                        <Plus class="btn-icon" />
                        Add Condition
                      </button>
                    </div>
                    <div class="conditions-list">
                      <div
                        v-for="(condition, index) in policyForm.conditions"
                        :key="index"
                        class="condition-card"
                      >
                        <div class="condition-header">
                          <h4>Condition {{ index + 1 }}</h4>
                          <button
                            type="button"
                            @click="removeABACCondition(index)"
                            class="btn-remove"
                          >
                            <Trash2 class="icon" />
                          </button>
                        </div>
                        <div class="form-group">
                          <label>Attribute</label>
                          <Dropdown
                            v-model="condition.attribute"
                            :options="attributeOptions"
                            placeholder="Select attribute..."
                          />
                        </div>
                        <div class="form-row">
                          <div class="form-group">
                            <label>Operator</label>
                            <Dropdown
                              v-model="condition.operator"
                              :options="operatorOptions"
                              placeholder="Select operator..."
                            />
                          </div>
                          <div class="form-group">
                            <label>Logical Operator</label>
                            <Dropdown
                              v-model="condition.logicalOperator"
                              :options="logicalOperatorOptions"
                              placeholder="None (First Condition)"
                            />
                            <small>How to combine with previous condition</small>
                          </div>
                        </div>
                        <div class="form-group">
                          <label>Value</label>
                          <input
                            v-model="condition.value"
                            type="text"
                            placeholder="e.g., admin or [admin, viewer] or {{resource.department}}"
                            required
                          />
                          <small>Use {{resource.attribute}} or {{subject.attribute}} for dynamic values</small>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- Visual Builder Tab -->
                <div v-if="editorTab === 'visual'" class="editor-content visual-builder-content">
                  <PolicyVisualBuilder
                    :policy-type="policyForm.type"
                    :model-value="getVisualBuilderRules()"
                    @update:model-value="handleVisualBuilderUpdate"
                  />
                </div>

                <!-- Code Tab -->
                <div v-if="editorTab === 'code'" class="editor-content code-editor-content">
                  <PolicyJSONEditor
                    v-model="jsonEditorValue"
                    language="json"
                    @update:model-value="handleJSONEditorUpdate"
                  />
                </div>

                <!-- Preview Tab -->
                <div v-if="editorTab === 'preview'" class="editor-content">
                  <div class="preview-section">
                    <h3>Policy Preview</h3>
                    <pre class="policy-preview">{{ JSON.stringify(getPolicyJSON(), null, 2) }}</pre>
                  </div>
                  <div class="preview-section">
                    <h3>Visualization</h3>
                    <PolicyVisualization :policy="getPolicyForVisualization()" />
                  </div>
                  <div class="preview-section">
                    <h3>Validation</h3>
                    <div v-if="validationErrors.length > 0" class="validation-errors">
                      <div
                        v-for="(error, index) in validationErrors"
                        :key="index"
                        class="validation-error"
                      >
                        <AlertTriangle class="error-icon" />
                        {{ error }}
                      </div>
                    </div>
                    <div v-else class="validation-success">
                      <CheckCircle2 class="success-icon" />
                      Policy is valid
                    </div>
                  </div>
                </div>

                <!-- Versions Tab -->
                <div v-if="editorTab === 'versions'" class="editor-content">
                  <div class="versions-section">
                    <h3>Version History</h3>
                    <div v-if="policyVersions.length > 0" class="versions-list">
                      <div
                        v-for="version in policyVersions"
                        :key="version.version"
                        class="version-item"
                      >
                        <div class="version-header">
                          <span class="version-number">v{{ version.version }}</span>
                          <span class="version-date">{{ formatDate(version.date) }}</span>
                        </div>
                        <button
                          @click="compareVersions(editingPolicy!)"
                          class="btn-compare-version"
                        >
                          Compare with Current
                        </button>
                      </div>
                    </div>
                    <div v-else class="empty-versions">
                      <p>No version history available</p>
                    </div>
                  </div>
                </div>

                <!-- Comparison Tab -->
                <div v-if="editorTab === 'comparison'" class="editor-content">
                  <SystemStateDiffPanel v-if="editingPolicy" :policy-id="editingPolicy" />
                </div>

                <!-- Gap Analysis Tab -->
                <div v-if="editorTab === 'gaps'" class="editor-content">
                  <GapAnalysisView v-if="editingPolicy" :policy-id="editingPolicy" />
                </div>

                <!-- Tags Tab -->
                <div v-if="editorTab === 'tags'" class="editor-content">
                  <div v-if="selectedResourceId" class="tags-section">
                    <TagComparisonPanel
                      :resource-id="selectedResourceId"
                      :policy-id="editingPolicy!"
                    />
                  </div>
                  <div v-else class="empty-tags-state">
                    <p>Select a resource to compare tags</p>
                    <input
                      v-model="selectedResourceId"
                      type="text"
                      placeholder="Enter resource ID..."
                      class="resource-input"
                    />
                  </div>
                </div>

                <!-- Comments Tab -->
                <div v-if="editorTab === 'comments'" class="editor-content">
                  <PolicyComments v-if="editingPolicy" :policy-id="editingPolicy" />
                </div>

                <!-- Approvals Tab -->
                <div v-if="editorTab === 'approvals'" class="editor-content">
                  <PolicyApprovals v-if="editingPolicy" :policy-id="editingPolicy" />
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="validationErrors.length > 0">
                    Save Policy
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Compare Versions Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCompareModal" class="modal-overlay" @click="closeCompareModal">
          <div class="modal-content compare-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <GitCompare class="modal-title-icon" />
                <h2>Compare Policy Versions</h2>
              </div>
              <button @click="closeCompareModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <PolicyDiffViewer
                v-if="comparingPolicyId"
                :policy-id="comparingPolicyId"
                :versions="policyVersions"
              />
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Teleport } from 'vue';
import {
  Shield,
  Plus,
  Edit,
  History,
  TestTube,
  X,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  GitCompare
} from 'lucide-vue-next';
import Dropdown from '../../components/Dropdown.vue';
import Breadcrumb from '../../components/Breadcrumb.vue';
import PolicyVisualBuilder from '../../components/policies/PolicyVisualBuilder.vue';
import PolicyVisualization from '../../components/policies/PolicyVisualization.vue';
import PolicyJSONEditor from '../../components/policies/PolicyJSONEditor.vue';
import PolicyDiffViewer from '../../components/policies/PolicyDiffViewer.vue';
import GapAnalysisView from '../../components/policies/GapAnalysisView.vue';
import SystemStateDiffPanel from '../../components/policies/SystemStateDiffPanel.vue';
import TagComparisonPanel from '../../components/policies/TagComparisonPanel.vue';
import PolicyComments from '../../components/policies/PolicyComments.vue';
import PolicyApprovals from '../../components/policies/PolicyApprovals.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Access Control', to: '/policies' },
  { label: 'Access Control' }
];

const searchQuery = ref('');
const filterType = ref('');
const filterStatus = ref('');
const showCreateModal = ref(false);
const editingPolicy = ref<string | null>(null);
const editorTab = ref<'basic' | 'rules' | 'visual' | 'code' | 'preview' | 'versions' | 'comparison' | 'gaps' | 'tags'>('basic');
const selectedResourceId = ref<string | null>(null);
const jsonEditorValue = ref('');
const loading = ref(false);
const error = ref<string | null>(null);
const showCompareModal = ref(false);
const comparingPolicyId = ref<string | null>(null);
const policyVersions = ref<Array<{ version: string; date: Date }>>([]);

// Policies data from API
const policies = ref<any[]>([]);
const tests = ref<any[]>([]);
const testCountsByPolicy = ref<Record<string, number>>({});

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'RBAC', value: 'rbac' },
  { label: 'ABAC', value: 'abac' }
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Active', value: 'active' },
  { label: 'Draft', value: 'draft' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const filteredPolicies = computed(() => {
  let filtered = policies.value;

  if (filterType.value === 'rbac') {
    filtered = filtered.filter(p => p.type === 'rbac');
  } else if (filterType.value === 'abac') {
    filtered = filtered.filter(p => p.type === 'abac');
  }

  return filtered.filter(policy => {
    const matchesSearch = policy.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         policy.description.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || policy.type === filterType.value;
    const matchesStatus = !filterStatus.value || policy.status === filterStatus.value;
    return matchesSearch && matchesType && matchesStatus;
  });
});

const policyForm = ref({
  name: '',
  description: '',
  type: 'rbac',
  version: '1.0.0',
  status: 'draft',
  effect: 'allow',
  priority: 100,
  rules: [] as any[],
  conditions: [] as any[]
});

// For RBAC condition management
const conditionKeys = ref<Record<number, string[]>>({});
const conditionValues = ref<Record<number, string[]>>({});

const viewPolicy = (id: string) => {
  router.push(`/policies/${id}`);
};

const editPolicy = async (id: string) => {
  try {
    loading.value = true;
    const response = await axios.get(`/api/policies/${id}`);
    const policy = response.data;
    
    editingPolicy.value = id;
    editorTab.value = 'basic';
    policyForm.value = {
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      version: policy.version,
      status: policy.status,
      effect: policy.effect || 'allow',
      priority: policy.priority || 100,
      rules: policy.rules || [],
      conditions: policy.conditions || []
    };
    initializeConditionArrays();
    
    // Load versions for this policy
    try {
      const versionsResponse = await axios.get(`/api/policies/${id}/versions`);
      policyVersions.value = versionsResponse.data.map((v: any) => ({
        version: v.version,
        date: new Date(v.date || v.createdAt),
      }));
    } catch (err) {
      console.error('Failed to load versions', err);
      policyVersions.value = [];
    }
    
    showCreateModal.value = true;
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load policy';
    console.error('Error loading policy:', err);
  } finally {
    loading.value = false;
  }
};

const viewVersions = (id: string) => {
  router.push(`/policies/${id}?tab=changelog`);
};

const compareVersions = async (id: string) => {
  comparingPolicyId.value = id;
  showCompareModal.value = true;
  
  // Load versions for this policy
  try {
    const response = await axios.get(`/api/policies/${id}/versions`);
    policyVersions.value = response.data.map((v: any) => ({
      version: v.version,
      date: new Date(v.date || v.createdAt),
    }));
  } catch (err) {
    console.error('Failed to load versions', err);
    policyVersions.value = [];
  }
};

const viewGapAnalysis = async (id: string) => {
  await editPolicy(id);
  editorTab.value = 'gaps';
};

const viewSystemState = async (id: string) => {
  await editPolicy(id);
  editorTab.value = 'comparison';
};

const closeCompareModal = () => {
  showCompareModal.value = false;
  comparingPolicyId.value = null;
  policyVersions.value = [];
};

const testPolicy = (id: string) => {
  router.push(`/policies/${id}?tab=overview`);
};

const viewTestsUsingPolicy = (policyId: string) => {
  router.push(`/tests/individual?policyId=${policyId}`);
};

const loadPolicies = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/policies');
    policies.value = response.data.map((p: any) => ({
      ...p,
      lastUpdated: new Date(p.updatedAt),
      ruleCount: p.ruleCount || (p.type === 'rbac' ? (p.rules?.length || 0) : (p.conditions?.length || 0))
    }));
    await loadTests();
  } catch (err: any) {
    error.value = err.message || 'Failed to load policies';
    console.error('Error loading policies:', err);
  } finally {
    loading.value = false;
  }
};

const loadTests = async () => {
  try {
    const response = await axios.get('/api/v1/tests?testType=access-control');
    tests.value = response.data;
    
    testCountsByPolicy.value = {};
    policies.value.forEach(policy => {
      const count = tests.value.filter(test => 
        test.testType === 'access-control' && 
        test.policyId === policy.id
      ).length;
      testCountsByPolicy.value[policy.id] = count;
    });
  } catch (err) {
    console.error('Error loading tests:', err);
  }
};

const getTestCount = (policyId: string): number => {
  return testCountsByPolicy.value[policyId] || 0;
};

const savePolicy = async () => {
  if (validationErrors.value.length > 0) {
    editorTab.value = 'preview';
    return;
  }
  
  try {
    loading.value = true;
    error.value = null;
    
    const policyData = {
      name: policyForm.value.name,
      description: policyForm.value.description,
      type: policyForm.value.type,
      version: policyForm.value.version,
      status: policyForm.value.status,
      effect: policyForm.value.effect,
      priority: policyForm.value.priority,
      rules: policyForm.value.rules,
      conditions: policyForm.value.conditions,
    };
    
    if (editingPolicy.value) {
      await axios.patch(`/api/policies/${editingPolicy.value}`, policyData);
    } else {
      await axios.post('/api/policies', policyData);
    }
    
    await loadPolicies();
    closeModal();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to save policy';
    console.error('Error saving policy:', err);
  } finally {
    loading.value = false;
  }
};

const deletePolicy = async (id: string) => {
  if (!confirm('Are you sure you want to delete this policy?')) {
    return;
  }
  
  try {
    loading.value = true;
    await axios.delete(`/api/policies/${id}`);
    await loadPolicies();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to delete policy';
    console.error('Error deleting policy:', err);
  } finally {
    loading.value = false;
  }
};

const getVisualBuilderRules = () => {
  if (policyForm.value.type === 'rbac') {
    // Convert policy form rules to visual builder format
    return policyForm.value.rules.map((rule: any) => ({
      id: rule.id || `rule-${Date.now()}`,
      description: rule.description || '',
      effect: rule.effect || 'allow',
      conditions: Object.entries(rule.conditions || {}).map(([key, value]) => ({
        key,
        value: Array.isArray(value) ? JSON.stringify(value) : String(value),
      })),
    }));
  } else {
    return policyForm.value.conditions || [];
  }
};

const handleVisualBuilderUpdate = (updatedRules: any[]) => {
  if (policyForm.value.type === 'rbac') {
    // Convert visual builder format to policy form format
    policyForm.value.rules = updatedRules.map((rule: any) => ({
      id: rule.id,
      description: rule.description,
      effect: rule.effect,
      conditions: rule.conditions.reduce((acc: any, cond: any) => {
        if (cond.key && cond.value) {
          // Try to parse arrays/objects, otherwise use as string
          try {
            const parsed = JSON.parse(cond.value);
            acc[cond.key] = parsed;
          } catch {
            acc[cond.key] = cond.value;
          }
        }
        return acc;
      }, {}),
    }));
  } else {
    policyForm.value.conditions = updatedRules;
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingPolicy.value = null;
  editorTab.value = 'basic';
  policyForm.value = {
    name: '',
    description: '',
    type: 'rbac',
    version: '1.0.0',
    status: 'draft',
    effect: 'allow',
    priority: 100,
    rules: [],
    conditions: []
  };
  conditionKeys.value = {};
  conditionValues.value = {};
  jsonEditorValue.value = '';
};

// RBAC Rule Management
const addRBACRule = () => {
  const newRule = {
    id: `rule-${Date.now()}`,
    description: '',
    effect: 'allow',
    conditions: {}
  };
  policyForm.value.rules.push(newRule);
  const index = policyForm.value.rules.length - 1;
  conditionKeys.value[index] = [];
  conditionValues.value[index] = [];
};

const removeRule = (index: number) => {
  policyForm.value.rules.splice(index, 1);
  delete conditionKeys.value[index];
  delete conditionValues.value[index];
  // Reindex
  const newKeys: Record<number, string[]> = {};
  const newValues: Record<number, string[]> = {};
  Object.keys(conditionKeys.value).forEach((key, i) => {
    newKeys[i] = conditionKeys.value[Number(key)];
    newValues[i] = conditionValues.value[Number(key)];
  });
  conditionKeys.value = newKeys;
  conditionValues.value = newValues;
};

const addCondition = (ruleIndex: number) => {
  if (!conditionKeys.value[ruleIndex]) {
    conditionKeys.value[ruleIndex] = [];
    conditionValues.value[ruleIndex] = [];
  }
  conditionKeys.value[ruleIndex].push('');
  conditionValues.value[ruleIndex].push('');
  updateRuleConditions(ruleIndex);
};

const removeCondition = (ruleIndex: number, condIndex: number) => {
  conditionKeys.value[ruleIndex].splice(condIndex, 1);
  conditionValues.value[ruleIndex].splice(condIndex, 1);
  updateRuleConditions(ruleIndex);
};

const updateConditionKey = (ruleIndex: number, condIndex: number, event: Event) => {
  const target = event.target as HTMLInputElement;
  conditionKeys.value[ruleIndex][condIndex] = target.value;
  updateRuleConditions(ruleIndex);
};

const updateConditionValue = (ruleIndex: number, condIndex: number, event: Event) => {
  const target = event.target as HTMLInputElement;
  conditionValues.value[ruleIndex][condIndex] = target.value;
  updateRuleConditions(ruleIndex);
};

const updateRuleConditions = (ruleIndex: number) => {
  const conditions: Record<string, any> = {};
  const keys = conditionKeys.value[ruleIndex] || [];
  const values = conditionValues.value[ruleIndex] || [];
  
  keys.forEach((key, index) => {
    if (key && values[index]) {
      const value = values[index];
      if (value.startsWith('[') && value.endsWith(']')) {
        try {
          conditions[key] = JSON.parse(value);
        } catch {
          conditions[key] = value;
        }
      } else {
        conditions[key] = value;
      }
    }
  });
  
  policyForm.value.rules[ruleIndex].conditions = conditions;
};

const initializeConditionArrays = () => {
  policyForm.value.rules.forEach((rule, index) => {
    const keys = Object.keys(rule.conditions);
    const values = Object.values(rule.conditions);
    conditionKeys.value[index] = keys;
    conditionValues.value[index] = values.map(v => 
      Array.isArray(v) ? JSON.stringify(v) : String(v)
    );
  });
};

// ABAC Condition Management
const addABACCondition = () => {
  policyForm.value.conditions.push({
    attribute: '',
    operator: 'equals',
    value: '',
    logicalOperator: ''
  });
};

const removeABACCondition = (index: number) => {
  policyForm.value.conditions.splice(index, 1);
};

// Validation
const validationErrors = computed(() => {
  const errors: string[] = [];
  
  if (!policyForm.value.name) {
    errors.push('Policy name is required');
  }
  
  if (policyForm.value.type === 'rbac') {
    if (policyForm.value.rules.length === 0) {
      errors.push('At least one rule is required for RBAC policies');
    }
    policyForm.value.rules.forEach((rule, index) => {
      if (!rule.id) {
        errors.push(`Rule ${index + 1}: ID is required`);
      }
      if (Object.keys(rule.conditions).length === 0) {
        errors.push(`Rule ${index + 1}: At least one condition is required`);
      }
    });
  } else {
    if (policyForm.value.conditions.length === 0) {
      errors.push('At least one condition is required for ABAC policies');
    }
    policyForm.value.conditions.forEach((condition, index) => {
      if (!condition.attribute) {
        errors.push(`Condition ${index + 1}: Attribute is required`);
      }
      if (!condition.operator) {
        errors.push(`Condition ${index + 1}: Operator is required`);
      }
      if (!condition.value) {
        errors.push(`Condition ${index + 1}: Value is required`);
      }
    });
  }
  
  return errors;
});

const getPolicyJSON = () => {
  if (policyForm.value.type === 'rbac') {
    return {
      name: policyForm.value.name,
      version: policyForm.value.version,
      rules: policyForm.value.rules.map(rule => ({
        id: rule.id,
        description: rule.description,
        effect: rule.effect,
        conditions: rule.conditions
      }))
    };
  } else {
    return {
      id: editingPolicy.value || `policy-${Date.now()}`,
      name: policyForm.value.name,
      description: policyForm.value.description,
      effect: policyForm.value.effect,
      priority: policyForm.value.priority,
      conditions: policyForm.value.conditions
    };
  }
};

const getPolicyForVisualization = () => {
  return {
    type: policyForm.value.type,
    name: policyForm.value.name,
    rules: policyForm.value.rules,
    conditions: policyForm.value.conditions,
    effect: policyForm.value.effect,
    priority: policyForm.value.priority,
  };
};

const policyTypeOptions = computed(() => [
  { label: 'RBAC', value: 'rbac' },
  { label: 'ABAC', value: 'abac' }
]);

const effectOptions = computed(() => [
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' }
]);

const policyStatusOptions = computed(() => [
  { label: 'Draft', value: 'draft' },
  { label: 'Active', value: 'active' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const attributeOptions = computed(() => ({
  'Subject Attributes': [
    { label: 'subject.department', value: 'subject.department' },
    { label: 'subject.clearanceLevel', value: 'subject.clearanceLevel' },
    { label: 'subject.projectAccess', value: 'subject.projectAccess' },
    { label: 'subject.dataClassification', value: 'subject.dataClassification' },
    { label: 'subject.location', value: 'subject.location' },
    { label: 'subject.employmentType', value: 'subject.employmentType' },
    { label: 'subject.certifications', value: 'subject.certifications' }
  ],
  'Resource Attributes': [
    { label: 'resource.dataClassification', value: 'resource.dataClassification' },
    { label: 'resource.department', value: 'resource.department' },
    { label: 'resource.project', value: 'resource.project' },
    { label: 'resource.region', value: 'resource.region' },
    { label: 'resource.requiresCertification', value: 'resource.requiresCertification' },
    { label: 'resource.minClearanceLevel', value: 'resource.minClearanceLevel' }
  ],
  'Context Attributes': [
    { label: 'context.location', value: 'context.location' },
    { label: 'context.timeOfDay', value: 'context.timeOfDay' },
    { label: 'context.ipAddress', value: 'context.ipAddress' }
  ]
}));

const operatorOptions = computed(() => [
  { label: 'Equals', value: 'equals' },
  { label: 'Not Equals', value: 'notEquals' },
  { label: 'In', value: 'in' },
  { label: 'Not In', value: 'notIn' },
  { label: 'Contains', value: 'contains' },
  { label: 'Starts With', value: 'startsWith' },
  { label: 'Ends With', value: 'endsWith' },
  { label: 'Regex Match', value: 'regex' },
  { label: 'Greater Than', value: 'greaterThan' },
  { label: 'Less Than', value: 'lessThan' }
]);

const logicalOperatorOptions = computed(() => [
  { label: 'None (First Condition)', value: '' },
  { label: 'AND', value: 'AND' },
  { label: 'OR', value: 'OR' }
]);

watch(() => policyForm.value.type, () => {
  if (policyForm.value.type === 'rbac' && policyForm.value.rules.length === 0) {
    addRBACRule();
  } else if (policyForm.value.type === 'abac' && policyForm.value.conditions.length === 0) {
    addABACCondition();
  }
  updateJSONEditorValue();
});

watch(() => editorTab.value, (newTab) => {
  if (newTab === 'code') {
    updateJSONEditorValue();
  }
});

watch([() => policyForm.value.rules, () => policyForm.value.conditions, () => policyForm.value.type], () => {
  if (editorTab.value !== 'code') {
    updateJSONEditorValue();
  }
});

const updateJSONEditorValue = () => {
  jsonEditorValue.value = JSON.stringify(getPolicyJSON(), null, 2);
};

const handleJSONEditorUpdate = (value: string) => {
  jsonEditorValue.value = value;
  try {
    const parsed = JSON.parse(value);
    
    // Update policy form from JSON
    if (parsed.name) policyForm.value.name = parsed.name;
    if (parsed.description) policyForm.value.description = parsed.description;
    if (parsed.version) policyForm.value.version = parsed.version;
    if (parsed.status) policyForm.value.status = parsed.status;
    if (parsed.effect) policyForm.value.effect = parsed.effect;
    if (parsed.priority !== undefined) policyForm.value.priority = parsed.priority;
    
    if (policyForm.value.type === 'rbac' && parsed.rules) {
      policyForm.value.rules = parsed.rules.map((rule: any) => ({
        id: rule.id,
        description: rule.description,
        effect: rule.effect,
        conditions: rule.conditions || {},
      }));
      initializeConditionArrays();
    } else if (policyForm.value.type === 'abac' && parsed.conditions) {
      policyForm.value.conditions = parsed.conditions;
    }
  } catch (error) {
    // Invalid JSON - don't update form
    console.error('Invalid JSON in editor:', error);
  }
};

const formatDate = (date: Date | string): string => {
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - dateObj.getTime()) / (24 * 60 * 60 * 1000));
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  return dateObj.toLocaleDateString();
};

onMounted(() => {
  loadPolicies();
});
</script>

<style scoped>
/* Import styles from Policies.vue - simplified version */
.policies-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-lg);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.filters {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  flex-wrap: wrap;
}

.search-input,
.filter-dropdown {
  flex: 1;
  min-width: 200px;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.search-input::placeholder {
  color: var(--color-text-muted);
}

.policies-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
}

.policy-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  cursor: pointer;
  transition: var(--transition-all);
}

.policy-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-primary-hover);
}

.policy-header {
  margin-bottom: var(--spacing-sm);
}

.policy-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.policy-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.policy-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.status-active {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-draft {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-deprecated {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
}

.policy-meta {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
  margin: 0;
}

.policy-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.policy-stats {
  display: flex;
  gap: var(--spacing-md);
  margin: var(--spacing-md) 0;
  padding: var(--spacing-sm) 0;
  border-top: var(--border-width-thin) solid var(--border-color-muted);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.stat {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.stat-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: var(--letter-spacing-wide);
}

.stat-value {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.policy-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
  margin-top: var(--spacing-sm);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
  transition: var(--transition-all);
}

.action-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.action-icon {
  width: 14px;
  height: 14px;
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  margin: 0 auto var(--spacing-md);
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon,
.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.btn-retry {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  margin-top: var(--spacing-md);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  backdrop-filter: blur(4px);
  z-index: var(--z-index-modal);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
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
  color: var(--color-text-secondary);
  cursor: pointer;
  border-radius: var(--border-radius-sm);
  transition: var(--transition-all);
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

.editor-tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.editor-tab {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.editor-tab.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.editor-content {
  max-height: 60vh;
  overflow-y: auto;
  padding-right: var(--spacing-sm);
}

.visual-builder-content {
  max-height: 70vh;
  padding: 0;
  overflow: hidden;
}

.code-editor-content {
  max-height: 70vh;
  padding: 0;
  overflow: hidden;
}

.form-group {
  margin-bottom: var(--spacing-xl);
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-sm);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
  font-size: var(--font-size-base);
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.form-group small {
  display: block;
  margin-top: var(--spacing-xs);
  color: var(--color-text-muted);
  font-size: var(--font-size-xs);
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
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-xl);
}

.section-header h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.btn-add {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.rules-list,
.conditions-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.rule-card,
.condition-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
}

.rule-header,
.condition-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.rule-header h4,
.condition-header h4 {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.btn-remove {
  padding: var(--spacing-xs);
  background: transparent;
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
  color: var(--color-error);
  cursor: pointer;
}

.condition-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.condition-key,
.condition-value {
  flex: 1;
  padding: var(--spacing-sm) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.condition-separator {
  color: var(--color-text-muted);
}

.btn-remove-small {
  padding: var(--spacing-xs);
  background: transparent;
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
  color: var(--color-error);
  cursor: pointer;
}

.btn-add-condition {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-sm);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
  margin-top: var(--spacing-sm);
}

.icon {
  width: 16px;
  height: 16px;
}

.policy-preview {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  color: var(--color-text-primary);
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
  overflow-x: auto;
}

.validation-errors {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.compare-modal {
  max-width: 90vw;
  width: 1200px;
  max-height: 90vh;
}

.compare-modal .modal-body {
  padding: 0;
  height: calc(90vh - 120px);
  overflow: hidden;
}

.validation-error {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-md);
  color: var(--color-error);
}

.validation-success {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-success-bg);
  border: var(--border-width-thin) solid var(--color-success);
  opacity: 0.3;
  border-radius: var(--border-radius-md);
  color: var(--color-success);
}

.success-icon {
  width: 20px;
  height: 20px;
}

.preview-section {
  margin-bottom: var(--spacing-lg);
}

.preview-section h3 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.versions-section,
.tags-section {
  padding: var(--spacing-md);
}

.versions-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.version-item {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.version-header {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.version-number {
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-md);
}

.version-date {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.btn-compare-version {
  padding: var(--spacing-xs) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-size: var(--font-size-sm);
}

.empty-versions,
.empty-tags-state {
  padding: var(--spacing-xl);
  text-align: center;
  color: var(--color-text-secondary);
}

.resource-input {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  width: 100%;
  max-width: 400px;
}
</style>
