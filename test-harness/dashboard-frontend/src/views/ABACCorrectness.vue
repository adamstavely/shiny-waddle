<template>
  <div class="abac-correctness-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">ABAC Correctness Testing</h1>
          <p class="page-description">Validate ABAC attributes, test policy completeness, performance, conflicts, and attribute propagation</p>
        </div>
        <button @click="showTestModal = true" class="btn-primary">
          <Play class="btn-icon" />
          Run Test
        </button>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
        <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
      </button>
    </div>

    <!-- Attributes Tab -->
    <div v-if="activeTab === 'attributes'" class="tab-content">
      <div class="results-grid">
        <div
          v-for="result in attributeResults"
          :key="result.id"
          class="result-card"
          @click="viewResultDetails(result)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.attribute }}</h3>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
          </div>

          <div class="result-details">
            <div class="detail-row">
              <span class="detail-label">Schema Valid:</span>
              <span class="detail-value" :class="result.schemaValid ? 'value-success' : 'value-error'">
                {{ result.schemaValid ? 'Yes' : 'No' }}
              </span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Source Trusted:</span>
              <span class="detail-value" :class="result.sourceTrusted ? 'value-success' : 'value-error'">
                {{ result.sourceTrusted ? 'Yes' : 'No' }}
              </span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Freshness Valid:</span>
              <span class="detail-value" :class="result.freshnessValid ? 'value-success' : 'value-error'">
                {{ result.freshnessValid ? 'Yes' : 'No' }}
              </span>
            </div>
            <div v-if="result.issues && result.issues.length > 0" class="detail-row">
              <span class="detail-label">Issues:</span>
              <span class="detail-value value-error">{{ result.issues.length }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="attributeResults.length === 0" class="empty-state">
        <Shield class="empty-icon" />
        <h3>No attribute validation results found</h3>
        <p>Run ABAC attribute validation tests to see results here</p>
      </div>
    </div>

    <!-- Completeness Tab -->
    <div v-if="activeTab === 'completeness'" class="tab-content">
      <div v-if="completenessResult" class="completeness-result">
        <div class="result-header">
          <h3>Policy Completeness Analysis</h3>
          <span class="result-status" :class="completenessResult.passed ? 'status-passed' : 'status-failed'">
            {{ completenessResult.passed ? 'Complete' : 'Incomplete' }}
          </span>
        </div>

        <div class="coverage-grid">
          <div class="coverage-card">
            <div class="coverage-label">Resource Types</div>
            <div class="coverage-value">{{ completenessResult.coverage.resourceTypes }}%</div>
            <div class="coverage-bar">
              <div 
                class="coverage-fill" 
                :style="{ width: `${completenessResult.coverage.resourceTypes}%` }"
              ></div>
            </div>
          </div>
          <div class="coverage-card">
            <div class="coverage-label">User Roles</div>
            <div class="coverage-value">{{ completenessResult.coverage.userRoles }}%</div>
            <div class="coverage-bar">
              <div 
                class="coverage-fill" 
                :style="{ width: `${completenessResult.coverage.userRoles}%` }"
              ></div>
            </div>
          </div>
          <div class="coverage-card">
            <div class="coverage-label">Actions</div>
            <div class="coverage-value">{{ completenessResult.coverage.actions }}%</div>
            <div class="coverage-bar">
              <div 
                class="coverage-fill" 
                :style="{ width: `${completenessResult.coverage.actions}%` }"
              ></div>
            </div>
          </div>
          <div class="coverage-card">
            <div class="coverage-label">Edge Cases</div>
            <div class="coverage-value">{{ completenessResult.coverage.edgeCases }}%</div>
            <div class="coverage-bar">
              <div 
                class="coverage-fill" 
                :style="{ width: `${completenessResult.coverage.edgeCases}%` }"
              ></div>
            </div>
          </div>
        </div>

        <div v-if="completenessResult.gaps && completenessResult.gaps.length > 0" class="gaps-section">
          <h4>Policy Gaps ({{ completenessResult.gaps.length }})</h4>
          <div
            v-for="gap in completenessResult.gaps"
            :key="`${gap.resourceType}-${gap.userRole}-${gap.action}`"
            class="gap-item"
            :class="`gap-${gap.severity}`"
          >
            <div class="gap-header">
              <span class="gap-resource">{{ gap.resourceType }}</span>
              <span class="gap-action">{{ gap.action }}</span>
              <span class="gap-severity">{{ gap.severity }}</span>
            </div>
            <div class="gap-details">
              <span>Role: {{ gap.userRole }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="empty-state">
        <Shield class="empty-icon" />
        <h3>No completeness test results</h3>
        <p>Run a completeness test to analyze policy coverage</p>
      </div>
    </div>

    <!-- Performance Tab -->
    <div v-if="activeTab === 'performance'" class="tab-content">
      <div v-if="performanceResult" class="performance-result">
        <div class="result-header">
          <h3>Performance Test Results</h3>
          <span class="result-status" :class="performanceResult.passed ? 'status-passed' : 'status-failed'">
            {{ performanceResult.passed ? 'Passed' : 'Failed' }}
          </span>
        </div>

        <div class="performance-metrics">
          <div class="metric-card">
            <div class="metric-label">Average Latency</div>
            <div class="metric-value">{{ performanceResult.averageLatency }}ms</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">P50 Latency</div>
            <div class="metric-value">{{ performanceResult.p50Latency }}ms</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">P95 Latency</div>
            <div class="metric-value">{{ performanceResult.p95Latency }}ms</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">P99 Latency</div>
            <div class="metric-value">{{ performanceResult.p99Latency }}ms</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Throughput</div>
            <div class="metric-value">{{ performanceResult.throughput }} req/s</div>
          </div>
          <div v-if="performanceResult.cacheHitRate !== undefined" class="metric-card">
            <div class="metric-label">Cache Hit Rate</div>
            <div class="metric-value">{{ (performanceResult.cacheHitRate * 100).toFixed(1) }}%</div>
          </div>
        </div>

        <div v-if="performanceResult.recommendations && performanceResult.recommendations.length > 0" class="recommendations-section">
          <h4>Recommendations</h4>
          <div
            v-for="rec in performanceResult.recommendations"
            :key="rec.type"
            class="recommendation-item"
            :class="`rec-${rec.impact}`"
          >
            <div class="rec-header">
              <span class="rec-type">{{ rec.type }}</span>
              <span class="rec-impact">{{ rec.impact }}</span>
            </div>
            <p class="rec-description">{{ rec.description }}</p>
          </div>
        </div>
      </div>

      <div v-else class="empty-state">
        <Shield class="empty-icon" />
        <h3>No performance test results</h3>
        <p>Run a performance test to analyze ABAC evaluation performance</p>
      </div>
    </div>

    <!-- Conflicts Tab -->
    <div v-if="activeTab === 'conflicts'" class="tab-content">
      <div v-if="conflictResult" class="conflict-result">
        <div class="result-header">
          <h3>Policy Conflict Analysis</h3>
          <span class="result-status" :class="conflictResult.passed ? 'status-passed' : 'status-failed'">
            {{ conflictResult.passed ? 'No Conflicts' : 'Conflicts Found' }}
          </span>
        </div>

        <div v-if="conflictResult.conflicts && conflictResult.conflicts.length > 0" class="conflicts-list">
          <div
            v-for="conflict in conflictResult.conflicts"
            :key="`${conflict.policy1}-${conflict.policy2}`"
            class="conflict-item"
          >
            <div class="conflict-header">
              <span class="conflict-policies">{{ conflict.policy1 }} vs {{ conflict.policy2 }}</span>
              <span class="conflict-type">{{ conflict.conflictType }}</span>
            </div>
            <div class="conflict-details">
              <div class="conflict-detail-row">
                <span>Resource:</span>
                <span>{{ conflict.resource }}</span>
              </div>
              <div class="conflict-detail-row">
                <span>Action:</span>
                <span>{{ conflict.action }}</span>
              </div>
              <div v-if="conflict.resolution" class="conflict-resolution">
                <span class="resolution-label">Resolution:</span>
                <span class="resolution-strategy">{{ conflict.resolution.strategy }}</span>
                <span class="resolution-decision" :class="conflict.resolution.resultingDecision">
                  {{ conflict.resolution.resultingDecision }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="empty-state">
        <Shield class="empty-icon" />
        <h3>No conflict test results</h3>
        <p>Run a conflict detection test to identify policy conflicts</p>
      </div>
    </div>

    <!-- Propagation Tab -->
    <div v-if="activeTab === 'propagation'" class="tab-content">
      <div v-if="propagationResult" class="propagation-result">
        <div class="result-header">
          <h3>Attribute Propagation Test</h3>
          <span class="result-status" :class="propagationResult.passed ? 'status-passed' : 'status-failed'">
            {{ propagationResult.passed ? 'Passed' : 'Failed' }}
          </span>
        </div>

        <div v-if="propagationResult.propagationResults && propagationResult.propagationResults.length > 0" class="propagation-list">
          <div
            v-for="prop in propagationResult.propagationResults"
            :key="`${prop.source}-${prop.target}-${prop.attribute}`"
            class="propagation-item"
          >
            <div class="propagation-header">
              <span class="propagation-path">{{ prop.source }} → {{ prop.target }}</span>
              <span class="propagation-attribute">{{ prop.attribute }}</span>
            </div>
            <div class="propagation-status">
              <span :class="prop.propagated ? 'value-success' : 'value-error'">
                {{ prop.propagated ? 'Propagated' : 'Not Propagated' }}
              </span>
              <span v-if="prop.transformed" class="value-info">Transformed</span>
              <span :class="prop.consistent ? 'value-success' : 'value-error'">
                {{ prop.consistent ? 'Consistent' : 'Inconsistent' }}
              </span>
              <span class="propagation-latency">{{ prop.latency }}ms</span>
            </div>
          </div>
        </div>

        <div v-if="propagationResult.consistencyIssues && propagationResult.consistencyIssues.length > 0" class="consistency-issues">
          <h4>Consistency Issues ({{ propagationResult.consistencyIssues.length }})</h4>
          <div
            v-for="issue in propagationResult.consistencyIssues"
            :key="`${issue.attribute}-${issue.system}`"
            class="consistency-item"
            :class="`issue-${issue.severity}`"
          >
            <span class="issue-attribute">{{ issue.attribute }}</span>
            <span class="issue-system">{{ issue.system }}</span>
            <span class="issue-message">{{ issue.issue }}</span>
          </div>
        </div>
      </div>

      <div v-else class="empty-state">
        <Shield class="empty-icon" />
        <h3>No propagation test results</h3>
        <p>Run a propagation test to analyze attribute propagation across systems</p>
      </div>
    </div>

    <!-- Test Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showTestModal" class="modal-overlay" @click="closeTestModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Run ABAC Correctness Test</h2>
              <button @click="closeTestModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="runTest" class="test-form">
                <div class="form-group">
                  <label>Test Type *</label>
                  <select v-model="testForm.type" required>
                    <option value="attributes">Attribute Validation</option>
                    <option value="completeness">Policy Completeness</option>
                    <option value="performance">Performance Testing</option>
                    <option value="conflicts">Conflict Detection</option>
                    <option value="propagation">Attribute Propagation</option>
                  </select>
                </div>

                <div v-if="testForm.type === 'attributes'" class="form-group">
                  <label>Attributes (JSON)</label>
                  <textarea v-model="testForm.attributes" rows="6" placeholder='[{"name": "department", "type": "string", ...}]'></textarea>
                </div>

                <div v-if="testForm.type === 'completeness'" class="form-group">
                  <label>Resource Types (comma-separated)</label>
                  <input v-model="testForm.resourceTypes" type="text" placeholder="user, document, file" />
                </div>

                <div v-if="testForm.type === 'completeness'" class="form-group">
                  <label>User Roles (comma-separated)</label>
                  <input v-model="testForm.userRoles" type="text" placeholder="admin, user, guest" />
                </div>

                <div v-if="testForm.type === 'conflicts'" class="form-group">
                  <label>Resolution Strategy *</label>
                  <select v-model="testForm.resolutionStrategy" required>
                    <option value="priority">Priority</option>
                    <option value="deny-override">Deny Override</option>
                    <option value="allow-override">Allow Override</option>
                    <option value="first-match">First Match</option>
                  </select>
                </div>

                <div v-if="testForm.type === 'propagation'" class="form-group">
                  <label>Source System *</label>
                  <input v-model="testForm.sourceSystem" type="text" placeholder="ldap" required />
                </div>

                <div v-if="testForm.type === 'propagation'" class="form-group">
                  <label>Target Systems (comma-separated) *</label>
                  <input v-model="testForm.targetSystems" type="text" placeholder="api, database" required />
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeTestModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="runningTest">
                    {{ runningTest ? 'Running...' : 'Run Test' }}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Result Detail Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showDetailModal && selectedResult" class="modal-overlay" @click="closeDetailModal">
          <div class="modal-content large" @click.stop>
            <div class="modal-header">
              <h2>Test Result Details</h2>
              <button @click="closeDetailModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="detail-section">
                <h3>Summary</h3>
                <div class="detail-grid">
                  <div class="detail-item">
                    <span class="detail-label">Status:</span>
                    <span :class="selectedResult.passed ? 'value-success' : 'value-error'">
                      {{ selectedResult.passed ? 'Passed' : 'Failed' }}
                    </span>
                  </div>
                  <div v-if="selectedResult.attribute" class="detail-item">
                    <span class="detail-label">Attribute:</span>
                    <span>{{ selectedResult.attribute }}</span>
                  </div>
                </div>
              </div>

              <div v-if="selectedResult.issues && selectedResult.issues.length > 0" class="detail-section">
                <h3>Issues ({{ selectedResult.issues.length }})</h3>
                <div
                  v-for="issue in selectedResult.issues"
                  :key="issue.type"
                  class="issue-card"
                  :class="`issue-${issue.severity}`"
                >
                  <div class="issue-header">
                    <span class="issue-type">{{ issue.type }}</span>
                    <span class="issue-severity">{{ issue.severity }}</span>
                  </div>
                  <p class="issue-message">{{ issue.message }}</p>
                </div>
              </div>
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
import axios from 'axios';
import {
  Shield,
  CheckCircle2,
  Gauge,
  AlertTriangle,
  Network,
  Play,
  X
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'ABAC Correctness Testing' }
];

const activeTab = ref<'attributes' | 'completeness' | 'performance' | 'conflicts' | 'propagation'>('attributes');
const showTestModal = ref(false);
const showDetailModal = ref(false);
const selectedResult = ref<any>(null);
const runningTest = ref(false);

const tabs = computed(() => [
  { id: 'attributes', label: 'Attributes', icon: Shield },
  { id: 'completeness', label: 'Completeness', icon: CheckCircle2 },
  { id: 'performance', label: 'Performance', icon: Gauge },
  { id: 'conflicts', label: 'Conflicts', icon: AlertTriangle },
  { id: 'propagation', label: 'Propagation', icon: Network }
]);

const testForm = ref({
  type: 'attributes',
  attributes: '',
  resourceTypes: '',
  userRoles: '',
  resolutionStrategy: 'priority',
  sourceSystem: '',
  targetSystems: ''
});

const attributeResults = ref<any[]>([]);
const completenessResult = ref<any>(null);
const performanceResult = ref<any>(null);
const conflictResult = ref<any>(null);
const propagationResult = ref<any>(null);

const runTest = async () => {
  runningTest.value = true;
  try {
    const baseUrl = '/api/abac-correctness';
    let response;
    
    switch (testForm.value.type) {
      case 'attributes':
        const attributes = testForm.value.attributes ? JSON.parse(testForm.value.attributes) : [];
        response = await axios.post(`${baseUrl}/validate-attributes`, {
          attributes
        });
        attributeResults.value.unshift({
          id: Date.now().toString(),
          ...response.data.results[0],
          timestamp: new Date()
        });
        break;
      case 'completeness':
        response = await axios.post(`${baseUrl}/test-completeness`, {
          resourceTypes: testForm.value.resourceTypes.split(',').map(s => s.trim()),
          userRoles: testForm.value.userRoles.split(',').map(s => s.trim()),
          actions: ['read', 'write', 'delete', 'create'],
          policies: []
        });
        completenessResult.value = response.data;
        break;
      case 'performance':
        response = await axios.post(`${baseUrl}/test-performance`, {
          policies: [],
          testRequests: [],
          loadConfig: {
            concurrentRequests: 10,
            duration: 60000
          }
        });
        performanceResult.value = response.data;
        break;
      case 'conflicts':
        response = await axios.post(`${baseUrl}/detect-conflicts`, {
          policies: [],
          resolutionStrategy: testForm.value.resolutionStrategy
        });
        conflictResult.value = response.data;
        break;
      case 'propagation':
        response = await axios.post(`${baseUrl}/test-propagation`, {
          sourceSystem: testForm.value.sourceSystem,
          targetSystems: testForm.value.targetSystems.split(',').map(s => s.trim()),
          attributes: [],
          transformationRules: []
        });
        propagationResult.value = response.data;
        break;
    }
    
    closeTestModal();
  } catch (error: any) {
    console.error('Error running test:', error);
    alert(error.response?.data?.message || 'Failed to run test');
  } finally {
    runningTest.value = false;
  }
};

const viewResultDetails = (result: any) => {
  selectedResult.value = result;
  showDetailModal.value = true;
};

const closeTestModal = () => {
  showTestModal.value = false;
  testForm.value = {
    type: 'attributes',
    attributes: '',
    resourceTypes: '',
    userRoles: '',
    resolutionStrategy: 'priority',
    sourceSystem: '',
    targetSystems: ''
  };
};

const closeDetailModal = () => {
  showDetailModal.value = false;
  selectedResult.value = null;
};

onMounted(() => {
  // Load initial data if needed
});
</script>

<style scoped>
/* Base styles - reuse from other views */
.abac-correctness-page {
  padding: 24px;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 24px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.page-title {
  font-size: 28px;
  font-weight: 600;
  margin: 0 0 8px 0;
  color: #e2e8f0;
}

.page-description {
  color: #94a3b8;
  margin: 0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: white;
  border: none;
  border-radius: 8px;
  font-weight: 500;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-primary:hover {
  opacity: 0.9;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #94a3b8;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-badge {
  background: rgba(79, 172, 254, 0.2);
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.75rem;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 20px;
}

.result-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.2s;
}

.result-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.result-header {
  margin-bottom: 16px;
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.result-name {
  font-size: 18px;
  font-weight: 600;
  margin: 0;
  color: #e2e8f0;
}

.result-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.result-details {
  margin-bottom: 16px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-label {
  color: #94a3b8;
}

.detail-value {
  color: #e2e8f0;
  font-weight: 500;
}

.value-success {
  color: #22c55e;
}

.value-error {
  color: #ef4444;
}

.value-info {
  color: #4facfe;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: #94a3b8;
}

.empty-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 20px;
  opacity: 0.5;
}

/* Completeness specific styles */
.completeness-result,
.performance-result,
.conflict-result,
.propagation-result {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.coverage-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin: 24px 0;
}

.coverage-card {
  background: rgba(79, 172, 254, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.coverage-label {
  color: #94a3b8;
  font-size: 0.875rem;
  margin-bottom: 8px;
}

.coverage-value {
  font-size: 24px;
  font-weight: 600;
  color: #4facfe;
  margin-bottom: 12px;
}

.coverage-bar {
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.coverage-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.gaps-section {
  margin-top: 24px;
}

.gaps-section h4 {
  color: #e2e8f0;
  margin-bottom: 16px;
}

.gap-item {
  padding: 12px;
  margin-bottom: 8px;
  border-radius: 6px;
  border-left: 3px solid;
}

.gap-item.gap-critical {
  background: rgba(239, 68, 68, 0.1);
  border-color: #ef4444;
}

.gap-item.gap-high {
  background: rgba(239, 68, 68, 0.1);
  border-color: #f87171;
}

.gap-header {
  display: flex;
  gap: 12px;
  margin-bottom: 4px;
}

.gap-resource,
.gap-action {
  font-weight: 600;
  color: #e2e8f0;
}

.gap-severity {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.gap-details {
  color: #94a3b8;
  font-size: 0.875rem;
}

/* Performance specific styles */
.performance-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin: 24px 0;
}

.metric-card {
  background: rgba(79, 172, 254, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.metric-label {
  color: #94a3b8;
  font-size: 0.875rem;
  margin-bottom: 8px;
}

.metric-value {
  font-size: 20px;
  font-weight: 600;
  color: #4facfe;
}

.recommendations-section {
  margin-top: 24px;
}

.recommendations-section h4 {
  color: #e2e8f0;
  margin-bottom: 16px;
}

.recommendation-item {
  padding: 12px;
  margin-bottom: 8px;
  border-radius: 6px;
  background: rgba(79, 172, 254, 0.05);
}

.rec-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 4px;
}

.rec-type {
  font-weight: 600;
  color: #e2e8f0;
}

.rec-impact {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.rec-description {
  color: #94a3b8;
  font-size: 0.875rem;
  margin: 0;
}

/* Conflict specific styles */
.conflicts-list {
  margin-top: 24px;
}

.conflict-item {
  padding: 16px;
  margin-bottom: 12px;
  background: rgba(239, 68, 68, 0.05);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: 8px;
}

.conflict-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.conflict-policies {
  font-weight: 600;
  color: #e2e8f0;
}

.conflict-type {
  padding: 4px 12px;
  background: rgba(239, 68, 68, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #ef4444;
}

.conflict-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.conflict-detail-row {
  display: flex;
  gap: 8px;
  color: #94a3b8;
  font-size: 0.875rem;
}

.conflict-resolution {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  align-items: center;
  gap: 12px;
}

.resolution-label {
  color: #94a3b8;
  font-weight: 500;
}

.resolution-strategy {
  color: #4facfe;
  font-weight: 600;
}

.resolution-decision {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.resolution-decision.allow {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.resolution-decision.deny {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

/* Propagation specific styles */
.propagation-list {
  margin-top: 24px;
}

.propagation-item {
  padding: 16px;
  margin-bottom: 12px;
  background: rgba(79, 172, 254, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.propagation-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.propagation-path {
  font-weight: 600;
  color: #e2e8f0;
}

.propagation-attribute {
  color: #4facfe;
  font-weight: 500;
}

.propagation-status {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.propagation-latency {
  color: #94a3b8;
  font-size: 0.875rem;
}

.consistency-issues {
  margin-top: 24px;
}

.consistency-issues h4 {
  color: #e2e8f0;
  margin-bottom: 16px;
}

.consistency-item {
  padding: 12px;
  margin-bottom: 8px;
  border-radius: 6px;
  display: flex;
  gap: 12px;
  align-items: center;
}

.consistency-item.issue-critical {
  background: rgba(239, 68, 68, 0.1);
  border-left: 3px solid #ef4444;
}

.consistency-item.issue-high {
  background: rgba(239, 68, 68, 0.1);
  border-left: 3px solid #f87171;
}

.issue-attribute {
  font-weight: 600;
  color: #e2e8f0;
}

.issue-system {
  color: #4facfe;
}

.issue-message {
  color: #94a3b8;
  flex: 1;
}

/* Modal styles - reuse from other views */
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
}

.modal-content {
  background: #1a1f2e;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  width: 90%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-content.large {
  max-width: 900px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  color: #e2e8f0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #94a3b8;
  cursor: pointer;
  padding: 4px;
}

.modal-close:hover {
  color: #e2e8f0;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.test-form {
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
  color: #e2e8f0;
  font-weight: 500;
}

.form-group select,
.form-group input,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #e2e8f0;
  font-family: 'Courier New', monospace;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.detail-section {
  margin-bottom: 24px;
}

.detail-section h3 {
  color: #e2e8f0;
  margin-bottom: 16px;
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

.issue-card {
  padding: 16px;
  margin-bottom: 12px;
  border-radius: 8px;
  border-left: 3px solid;
}

.issue-card.issue-critical {
  background: rgba(239, 68, 68, 0.1);
  border-color: #ef4444;
}

.issue-card.issue-high {
  background: rgba(239, 68, 68, 0.1);
  border-color: #f87171;
}

.issue-card.issue-medium {
  background: rgba(245, 158, 11, 0.1);
  border-color: #f59e0b;
}

.issue-card.issue-low {
  background: rgba(79, 172, 254, 0.1);
  border-color: #4facfe;
}

.issue-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.issue-type {
  font-weight: 600;
  color: #e2e8f0;
}

.issue-severity {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.issue-message {
  color: #94a3b8;
  margin: 8px 0;
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.3s;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
</style>

