<template>
  <div class="test-harness-detail-page">
    <div v-if="loading" class="loading">Loading test harness...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && harness" class="test-harness-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <h1 class="page-title">{{ harness.name }}</h1>
            <p v-if="harness.description" class="harness-description">{{ harness.description }}</p>
            <div class="harness-meta">
              <span v-if="harness.team" class="meta-item">
                <Users class="meta-icon" />
                {{ harness.team }}
              </span>
              <span class="meta-item">
                <List class="meta-icon" />
                {{ harness.testSuiteIds?.length || 0 }} test suites
              </span>
              <span class="meta-item">
                <Package class="meta-icon" />
                {{ harness.applicationIds?.length || 0 }} applications
              </span>
              <span class="meta-item">
                <Clock class="meta-icon" />
                Created {{ formatDate(harness.createdAt) }}
              </span>
            </div>
          </div>
          <div class="header-actions">
            <button @click="editHarness" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="deleteHarness" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
            <button @click="goBack" class="action-btn cancel-btn">
              <ArrowLeft class="action-icon" />
              Back
            </button>
          </div>
        </div>
      </div>

      <!-- Content Sections -->
      <div class="content-sections">
        <!-- Test Suites -->
        <div class="section-card">
          <div class="section-header">
            <List class="section-icon" />
            <h2 class="section-title">Test Suites</h2>
            <button @click="showAddSuiteModal = true" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Suite
            </button>
          </div>
          <div v-if="loadingSuites" class="loading">Loading test suites...</div>
          <div v-else-if="suitesError" class="error">{{ suitesError }}</div>
          <div v-else-if="suites.length === 0" class="empty-state">
            <List class="empty-icon" />
            <h3>No test suites in this harness</h3>
            <p>Add test suites to this harness</p>
            <button @click="showAddSuiteModal = true" class="btn-primary">
              Add Suite
            </button>
          </div>
          <div v-else class="suites-list">
            <div
              v-for="suite in suites"
              :key="suite.id"
              class="suite-card"
            >
              <div class="suite-content">
                <div class="suite-info">
                  <h3 class="suite-name">{{ suite.name }}</h3>
                  <p class="suite-meta">
                    {{ suite.application || suite.applicationId }}
                    <span v-if="suite.team"> • {{ suite.team }}</span>
                  </p>
                  <div class="suite-stats">
                    <span class="stat">
                      <TestTube class="stat-icon" />
                      {{ suite.testCount || 0 }} tests
                    </span>
                    <span class="stat" :class="`status-${suite.status || 'pending'}`">
                      <CheckCircle2 v-if="suite.status === 'passing'" class="stat-icon" />
                      <XCircle v-else-if="suite.status === 'failing'" class="stat-icon" />
                      <Clock v-else class="stat-icon" />
                      {{ suite.status || 'pending' }}
                    </span>
                  </div>
                </div>
                <div class="suite-actions">
                  <button @click="viewSuite(suite.id)" class="btn-secondary">
                    View Details
                  </button>
                  <button @click="removeSuite(suite.id)" class="btn-danger">
                    <Trash2 class="btn-icon-small" />
                    Remove
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Assigned Applications -->
        <div class="section-card">
          <div class="section-header">
            <Package class="section-icon" />
            <h2 class="section-title">Assigned Applications</h2>
            <button @click="showAddApplicationModal = true" class="btn-small">
              <Plus class="btn-icon-small" />
              Assign Application
            </button>
          </div>
          <div v-if="loadingApplications" class="loading">Loading applications...</div>
          <div v-else-if="applicationsError" class="error">{{ applicationsError }}</div>
          <div v-else-if="applications.length === 0" class="empty-state">
            <Package class="empty-icon" />
            <h3>No applications assigned</h3>
            <p>Assign this harness to applications to run tests</p>
            <button @click="showAddApplicationModal = true" class="btn-primary">
              Assign Application
            </button>
          </div>
          <div v-else class="applications-list">
            <div
              v-for="app in applications"
              :key="app.id"
              class="application-card"
            >
              <div class="application-content">
                <div class="application-info">
                  <h3 class="application-name">{{ app.name }}</h3>
                  <p v-if="app.team" class="application-meta">{{ app.team }}</p>
                </div>
                <div class="application-actions">
                  <button @click="viewApplication(app.id)" class="btn-secondary">
                    View Details
                  </button>
                  <button @click="unassignApplication(app.id)" class="btn-danger">
                    <Trash2 class="btn-icon-small" />
                    Unassign
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Run Results -->
        <div class="section-card">
          <div class="section-header">
            <FileText class="section-icon" />
            <h2 class="section-title">Recent Run Results</h2>
          </div>
          <div class="empty-state">
            <Info class="empty-icon" />
            <p>Execution results will appear here after harness runs in CI/CD</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Add Suite Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddSuiteModal" class="modal-overlay" @click="showAddSuiteModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Add Test Suite to Harness</h2>
              <button @click="showAddSuiteModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="loadingAvailableSuites" class="loading">Loading test suites...</div>
              <div v-else-if="availableSuites.length === 0" class="empty-state">
                <p>No available test suites. All suites are already in this harness.</p>
              </div>
              <div v-else class="selection-list">
                <div
                  v-for="suite in availableSuites"
                  :key="suite.id"
                  class="selection-option"
                  @click="addSuite(suite.id)"
                >
                  <div class="option-info">
                    <span class="option-name">{{ suite.name }}</span>
                    <span class="option-meta">
                      {{ suite.application || suite.applicationId }}
                      <span v-if="suite.team"> • {{ suite.team }}</span>
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Add Application Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddApplicationModal" class="modal-overlay" @click="showAddApplicationModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Assign Application to Harness</h2>
              <button @click="showAddApplicationModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="loadingAvailableApplications" class="loading">Loading applications...</div>
              <div v-else-if="availableApplications.length === 0" class="empty-state">
                <p>No available applications. All applications are already assigned to this harness.</p>
              </div>
              <div v-else class="selection-list">
                <div
                  v-for="app in availableApplications"
                  :key="app.id"
                  class="selection-option"
                  @click="assignApplication(app.id)"
                >
                  <div class="option-info">
                    <span class="option-name">{{ app.name }}</span>
                    <span class="option-meta" v-if="app.team">
                      {{ app.team }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Edit Harness Modal -->
    <TestHarnessModal
      :show="showEditModal"
      :editing-harness="harness"
      @close="showEditModal = false"
      @saved="handleHarnessUpdated"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { Teleport } from 'vue';
import {
  Layers,
  List,
  Package,
  Edit,
  Trash2,
  ArrowLeft,
  Plus,
  X,
  Users,
  Clock,
  TestTube,
  CheckCircle2,
  XCircle,
  FileText,
  Info,
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestHarnessModal from '../components/TestHarnessModal.vue';
import type { TestHarness } from '../../core/types';

const router = useRouter();
const route = useRoute();

const harness = ref<TestHarness | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);

const suites = ref<any[]>([]);
const loadingSuites = ref(false);
const suitesError = ref<string | null>(null);

const applications = ref<any[]>([]);
const loadingApplications = ref(false);
const applicationsError = ref<string | null>(null);

const showAddSuiteModal = ref(false);
const availableSuites = ref<any[]>([]);
const loadingAvailableSuites = ref(false);

const showAddApplicationModal = ref(false);
const availableApplications = ref<any[]>([]);
const loadingAvailableApplications = ref(false);

const showEditModal = ref(false);

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests?tab=harnesses' },
  { label: harness.value?.name || 'Harness' },
]);

const loadHarness = async () => {
  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/test-harnesses/${route.params.id}`);
    harness.value = response.data;
    await Promise.all([loadSuites(), loadApplications()]);
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load test harness';
    console.error('Error loading harness:', err);
  } finally {
    loading.value = false;
  }
};

const loadSuites = async () => {
  if (!harness.value?.testSuiteIds || harness.value.testSuiteIds.length === 0) {
    suites.value = [];
    return;
  }

  loadingSuites.value = true;
  suitesError.value = null;
  try {
    const promises = harness.value.testSuiteIds.map(async (suiteId) => {
      try {
        const response = await axios.get(`/api/test-suites/${suiteId}`);
        return response.data;
      } catch (err) {
        console.error(`Error loading suite ${suiteId}:`, err);
        return null;
      }
    });

    const results = await Promise.all(promises);
    suites.value = results.filter(s => s !== null);
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to load test suites';
    console.error('Error loading suites:', err);
  } finally {
    loadingSuites.value = false;
  }
};

const loadApplications = async () => {
  if (!harness.value?.applicationIds || harness.value.applicationIds.length === 0) {
    applications.value = [];
    return;
  }

  loadingApplications.value = true;
  applicationsError.value = null;
  try {
    const promises = harness.value.applicationIds.map(async (appId) => {
      try {
        const response = await axios.get(`/api/applications/${appId}`);
        return response.data;
      } catch (err) {
        console.error(`Error loading application ${appId}:`, err);
        return null;
      }
    });

    const results = await Promise.all(promises);
    applications.value = results.filter(a => a !== null);
  } catch (err: any) {
    applicationsError.value = err.response?.data?.message || 'Failed to load applications';
    console.error('Error loading applications:', err);
  } finally {
    loadingApplications.value = false;
  }
};

const loadAvailableSuites = async () => {
  loadingAvailableSuites.value = true;
  try {
    const response = await axios.get('/api/test-suites');
    const allSuites = response.data || [];
    // Filter out suites already in the harness
    const currentSuiteIds = harness.value?.testSuiteIds || [];
    availableSuites.value = allSuites.filter(
      (s: any) => !currentSuiteIds.includes(s.id)
    );
  } catch (err) {
    console.error('Error loading available suites:', err);
    availableSuites.value = [];
  } finally {
    loadingAvailableSuites.value = false;
  }
};

const loadAvailableApplications = async () => {
  loadingAvailableApplications.value = true;
  try {
    const response = await axios.get('/api/applications');
    const allApplications = response.data || [];
    // Filter out applications already assigned to the harness
    const currentApplicationIds = harness.value?.applicationIds || [];
    availableApplications.value = allApplications.filter(
      (a: any) => !currentApplicationIds.includes(a.id)
    );
  } catch (err) {
    console.error('Error loading available applications:', err);
    availableApplications.value = [];
  } finally {
    loadingAvailableApplications.value = false;
  }
};

const addSuite = async (suiteId: string) => {
  try {
    await axios.post(`/api/test-harnesses/${route.params.id}/test-suites`, {
      suiteId,
    });
    showAddSuiteModal.value = false;
    await loadHarness();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to add test suite');
  }
};

const removeSuite = async (suiteId: string) => {
  if (!confirm('Are you sure you want to remove this test suite from the harness?')) {
    return;
  }

  try {
    await axios.delete(`/api/test-harnesses/${route.params.id}/test-suites/${suiteId}`);
    await loadHarness();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to remove test suite');
  }
};

const assignApplication = async (applicationId: string) => {
  try {
    await axios.post(`/api/test-harnesses/${route.params.id}/applications`, {
      applicationId,
    });
    showAddApplicationModal.value = false;
    await loadHarness();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to assign application');
  }
};

const unassignApplication = async (applicationId: string) => {
  if (!confirm('Are you sure you want to unassign this application from the harness?')) {
    return;
  }

  try {
    await axios.delete(`/api/test-harnesses/${route.params.id}/applications/${applicationId}`);
    await loadHarness();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to unassign application');
  }
};

const editHarness = () => {
  showEditModal.value = true;
};

const handleHarnessUpdated = async () => {
  showEditModal.value = false;
  await loadHarness();
};

const deleteHarness = async () => {
  if (!confirm('Are you sure you want to delete this test harness? This action cannot be undone.')) {
    return;
  }

  try {
    await axios.delete(`/api/test-harnesses/${route.params.id}`);
    router.push({ path: '/tests', query: { tab: 'harnesses' } });
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to delete harness');
  }
};

const viewSuite = (suiteId: string) => {
  router.push({ path: `/tests/${suiteId}` });
};

const viewApplication = (applicationId: string) => {
  router.push({ path: `/admin/applications/${applicationId}` });
};

const goBack = () => {
  router.push({ path: '/tests', query: { tab: 'harnesses' } });
};

const formatDate = (date: Date | string | null): string => {
  if (!date) return 'Unknown';
  return new Date(date).toLocaleDateString();
};

// Watch for modals to load available data
watch(showAddSuiteModal, (isShowing) => {
  if (isShowing) {
    loadAvailableSuites();
  }
});

watch(showAddApplicationModal, (isShowing) => {
  if (isShowing) {
    loadAvailableApplications();
  }
});

onMounted(() => {
  loadHarness();
});
</script>

<style scoped>
.test-harness-detail-page {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.loading,
.error {
  padding: 3rem;
  text-align: center;
  font-size: 1.125rem;
}

.error {
  color: #fc8181;
}

.detail-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 2rem;
  margin-top: 1rem;
}

.header-left {
  flex: 1;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.harness-description {
  color: #a0aec0;
  font-size: 1rem;
  margin: 0 0 1rem 0;
}

.harness-meta {
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #718096;
  font-size: 0.875rem;
}

.meta-icon {
  width: 16px;
  height: 16px;
}

.header-actions {
  display: flex;
  gap: 0.75rem;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  font-weight: 500;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.action-icon {
  width: 18px;
  height: 18px;
}

.edit-btn {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.edit-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.delete-btn {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.2);
}

.cancel-btn {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
}

.cancel-btn:hover {
  background: rgba(160, 174, 192, 0.2);
}

.content-sections {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.section-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
}

.section-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.btn-small {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.2);
}

.btn-icon-small {
  width: 14px;
  height: 14px;
}

.suites-list,
.applications-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.suite-card,
.application-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1.25rem;
  transition: all 0.2s;
}

.suite-card:hover,
.application-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
}

.suite-content,
.application-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.suite-info,
.application-info {
  flex: 1;
}

.suite-name,
.application-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.suite-meta,
.application-meta {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 0.75rem 0;
}

.suite-stats {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.stat {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #718096;
  font-size: 0.875rem;
}

.stat.status-passing {
  color: #22c55e;
}

.stat.status-failing {
  color: #fc8181;
}

.stat-icon {
  width: 14px;
  height: 14px;
}

.suite-actions,
.application-actions {
  display: flex;
  gap: 0.75rem;
}

.btn-secondary,
.btn-danger {
  padding: 0.5rem 1rem;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.btn-danger {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.btn-danger:hover {
  background: rgba(252, 129, 129, 0.2);
}

.empty-state {
  padding: 3rem;
  text-align: center;
  color: #718096;
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin: 0 auto 1rem;
  opacity: 0.5;
}

.empty-state h3 {
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.empty-state p {
  margin: 0 0 1.5rem 0;
}

.btn-primary {
  padding: 0.75rem 1.5rem;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #0f1419;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
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
  padding: 2rem;
}

.modal-content {
  background: #1a1f2e;
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 80vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1.5rem 2rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
  transition: all 0.2s;
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
  padding: 2rem;
  overflow-y: auto;
  flex: 1;
}

.selection-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-height: 400px;
  overflow-y: auto;
}

.selection-option {
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.selection-option:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.option-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.option-name {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.option-meta {
  font-size: 0.75rem;
  color: #718096;
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

