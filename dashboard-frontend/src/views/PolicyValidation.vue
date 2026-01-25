<template>
  <div class="policy-validation-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Policy Validation</h1>
          <p class="page-description">Detect conflicts, analyze coverage, and test policy performance</p>
        </div>
      </div>
    </div>

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
      </button>
    </div>

    <div class="tab-content">
      <div v-if="activeTab === 'conflicts'" class="validation-section">
        <div class="section-header">
          <div>
            <h2 class="section-title">Detect Policy Conflicts</h2>
            <p class="section-description">Identify overlapping or contradictory policies</p>
          </div>
          <button @click="detectConflicts" class="btn-primary" :disabled="loading">
            <FileSearch v-if="!loading" class="btn-icon" />
            <div v-else class="loading-spinner-small"></div>
            {{ loading ? 'Detecting...' : 'Detect Conflicts' }}
          </button>
        </div>

        <div v-if="conflicts.length > 0" class="conflicts-list">
          <div v-for="(conflict, idx) in conflicts" :key="idx" class="conflict-card">
            <div class="conflict-header">
              <AlertTriangle class="conflict-icon" />
              <div>
                <h3 class="conflict-title">{{ conflict.policy1 }} vs {{ conflict.policy2 }}</h3>
                <span class="conflict-type">{{ conflict.conflictType }}</span>
              </div>
            </div>
            <p class="conflict-description">{{ conflict.description }}</p>
            <div v-if="conflict.affectedResources.length > 0" class="affected-resources">
              <span class="resources-label">Affected Resources:</span>
              <div class="resource-tags">
                <span v-for="resource in conflict.affectedResources" :key="resource" class="resource-tag">
                  {{ resource }}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div v-else-if="!loading && conflicts.length === 0 && hasRunConflicts" class="empty-state">
          <CheckCircle2 class="empty-icon" />
          <h3>No Conflicts Found</h3>
          <p>All policies are compatible</p>
        </div>
      </div>

      <div v-if="activeTab === 'coverage'" class="validation-section">
        <div class="section-header">
          <div>
            <h2 class="section-title">Analyze Policy Coverage</h2>
            <p class="section-description">Check which resources have policy coverage</p>
          </div>
          <button @click="analyzeCoverage" class="btn-primary" :disabled="loading">
            <BarChart3 v-if="!loading" class="btn-icon" />
            <div v-else class="loading-spinner-small"></div>
            {{ loading ? 'Analyzing...' : 'Analyze Coverage' }}
          </button>
        </div>

        <div v-if="coverage" class="coverage-results">
          <div class="coverage-summary">
            <div class="summary-card">
              <div class="summary-value">{{ coverage.coveragePercentage.toFixed(1) }}%</div>
              <div class="summary-label">Coverage</div>
            </div>
            <div class="summary-card">
              <div class="summary-value">{{ coverage.resourcesWithPolicies }}</div>
              <div class="summary-label">With Policies</div>
            </div>
            <div class="summary-card">
              <div class="summary-value">{{ coverage.resourcesWithoutPolicies.length }}</div>
              <div class="summary-label">Without Policies</div>
            </div>
          </div>

          <div v-if="coverage.gaps.length > 0" class="gaps-section">
            <h3 class="gaps-title">Coverage Gaps</h3>
            <div class="gaps-list">
              <div v-for="(gap, idx) in coverage.gaps" :key="idx" class="gap-item">
                <span class="gap-resource">{{ gap.resource }}</span>
                <span class="gap-type">{{ gap.resourceType }}</span>
                <span class="gap-recommendation">{{ gap.recommendedPolicy }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="activeTab === 'performance'" class="validation-section">
        <div class="section-header">
          <div>
            <h2 class="section-title">Test Policy Performance</h2>
            <p class="section-description">Measure policy evaluation latency and throughput</p>
          </div>
          <button @click="testPerformance" class="btn-primary" :disabled="loading">
            <Zap v-if="!loading" class="btn-icon" />
            <div v-else class="loading-spinner-small"></div>
            {{ loading ? 'Testing...' : 'Test Performance' }}
          </button>
        </div>

        <div v-if="performance" class="performance-results">
          <div class="performance-metrics">
            <div class="metric-card">
              <div class="metric-value">{{ performance.averageTime.toFixed(2) }}ms</div>
              <div class="metric-label">Average Time</div>
            </div>
            <div class="metric-card">
              <div class="metric-value">{{ performance.p95.toFixed(2) }}ms</div>
              <div class="metric-label">P95</div>
            </div>
            <div class="metric-card">
              <div class="metric-value">{{ performance.p99.toFixed(2) }}ms</div>
              <div class="metric-label">P99</div>
            </div>
            <div class="metric-card">
              <div class="metric-value">{{ performance.minTime.toFixed(2) }}ms</div>
              <div class="metric-label">Min Time</div>
            </div>
            <div class="metric-card">
              <div class="metric-value">{{ performance.maxTime.toFixed(2) }}ms</div>
              <div class="metric-label">Max Time</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { FileSearch, BarChart3, Zap, AlertTriangle, CheckCircle2 } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policy Validation', to: '/policy-validation' },
];

const loading = ref(false);
const activeTab = ref('conflicts');
const conflicts = ref<any[]>([]);
const coverage = ref<any>(null);
const performance = ref<any>(null);
const hasRunConflicts = ref(false);

const tabs = [
  { id: 'conflicts', label: 'Conflicts', icon: AlertTriangle },
  { id: 'coverage', label: 'Coverage', icon: BarChart3 },
  { id: 'performance', label: 'Performance', icon: Zap },
];

const detectConflicts = async () => {
  loading.value = true;
  hasRunConflicts.value = true;
  try {
    const response = await axios.post('/api/policy-validation/detect-conflicts', {
      policies: [],
    });
    conflicts.value = response.data;
  } catch (error) {
    console.error('Error detecting conflicts:', error);
  } finally {
    loading.value = false;
  }
};

const analyzeCoverage = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/policy-validation/analyze-coverage', {
      resources: [],
      policies: [],
    });
    coverage.value = response.data;
  } catch (error) {
    console.error('Error analyzing coverage:', error);
  } finally {
    loading.value = false;
  }
};

const testPerformance = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/policy-validation/test-performance', {
      policy: { id: 'test', name: 'Test Policy', effect: 'allow', conditions: [] },
      iterations: 1000,
    });
    performance.value = response.data;
  } catch (error) {
    console.error('Error testing performance:', error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.policy-validation-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
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

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 32px;
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
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
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

.tab-content {
  min-height: 400px;
}

.validation-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
  gap: 24px;
  flex-wrap: wrap;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.section-description {
  font-size: 0.9rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: #ffffff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.conflicts-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.conflict-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-left: 4px solid #fc8181;
  border-radius: 8px;
  padding: 20px;
}

.conflict-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.conflict-icon {
  width: 24px;
  height: 24px;
  color: #fc8181;
  flex-shrink: 0;
}

.conflict-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.conflict-type {
  display: inline-block;
  padding: 4px 8px;
  background: rgba(252, 129, 129, 0.2);
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #fc8181;
  text-transform: capitalize;
}

.conflict-description {
  color: #a0aec0;
  margin-bottom: 12px;
  line-height: 1.5;
}

.affected-resources {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.resources-label {
  font-size: 0.875rem;
  color: #718096;
  margin-right: 8px;
}

.resource-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

.resource-tag {
  padding: 4px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
}

.coverage-results {
  margin-top: 24px;
}

.coverage-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.summary-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.summary-value {
  font-size: 2rem;
  font-weight: 700;
  color: #4facfe;
  margin-bottom: 8px;
}

.summary-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.gaps-section {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.gaps-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.gaps-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.gap-item {
  display: grid;
  grid-template-columns: 1fr 1fr 2fr;
  gap: 16px;
  padding: 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
  font-size: 0.875rem;
}

.gap-resource {
  color: #ffffff;
  font-weight: 600;
}

.gap-type {
  color: #a0aec0;
}

.gap-recommendation {
  color: #fbbf24;
}

.performance-results {
  margin-top: 24px;
}

.performance-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
}

.metric-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.metric-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #4facfe;
  margin-bottom: 8px;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #22c55e;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
}
</style>
