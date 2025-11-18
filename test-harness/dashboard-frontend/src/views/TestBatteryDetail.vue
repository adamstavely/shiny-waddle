<template>
  <div class="test-battery-detail-page">
    <div v-if="loading" class="loading">Loading test battery...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && battery" class="test-battery-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <h1 class="page-title">{{ battery.name }}</h1>
            <p v-if="battery.description" class="battery-description">{{ battery.description }}</p>
            <div class="battery-meta">
              <span v-if="battery.team" class="meta-item">
                <Users class="meta-icon" />
                {{ battery.team }}
              </span>
              <span class="meta-item">
                <Battery class="meta-icon" />
                {{ battery.harnessIds?.length || 0 }} harnesses
              </span>
              <span class="meta-item">
                <Clock class="meta-icon" />
                Created {{ formatDate(battery.createdAt) }}
              </span>
            </div>
          </div>
          <div class="header-actions">
            <button @click="editBattery" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="deleteBattery" class="action-btn delete-btn">
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
        <!-- Execution Configuration -->
        <div class="section-card">
          <div class="section-header">
            <Settings class="section-icon" />
            <h2 class="section-title">Execution Configuration</h2>
          </div>
          <div class="config-details">
            <div class="config-item">
              <span class="config-label">Execution Mode</span>
              <span class="config-value execution-mode" :class="battery.executionConfig?.executionMode || 'sequential'">
                {{ battery.executionConfig?.executionMode || 'sequential' }}
              </span>
            </div>
            <div v-if="battery.executionConfig?.timeout" class="config-item">
              <span class="config-label">Timeout</span>
              <span class="config-value">{{ battery.executionConfig.timeout }} seconds</span>
            </div>
            <div class="config-item">
              <span class="config-label">Stop on Failure</span>
              <span class="config-value">
                {{ battery.executionConfig?.stopOnFailure ? 'Yes' : 'No' }}
              </span>
            </div>
          </div>
        </div>

        <!-- Test Harnesses -->
        <div class="section-card">
          <div class="section-header">
            <Layers class="section-icon" />
            <h2 class="section-title">Test Harnesses</h2>
            <button @click="showAddHarnessModal = true" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Harness
            </button>
          </div>
          <div v-if="loadingHarnesses" class="loading">Loading harnesses...</div>
          <div v-else-if="harnessesError" class="error">{{ harnessesError }}</div>
          <div v-else-if="harnesses.length === 0" class="empty-state">
            <Layers class="empty-icon" />
            <h3>No harnesses in this battery</h3>
            <p>Add test harnesses to organize test execution</p>
            <button @click="showAddHarnessModal = true" class="btn-primary">
              Add Harness
            </button>
          </div>
          <div v-else class="harnesses-list">
            <div
              v-for="harness in harnesses"
              :key="harness.id"
              class="harness-card"
            >
              <div class="harness-content">
                <div class="harness-info">
                  <h3 class="harness-name">{{ harness.name }}</h3>
                  <p v-if="harness.description" class="harness-description">{{ harness.description }}</p>
                  <div class="harness-stats">
                    <span class="stat">
                      <List class="stat-icon" />
                      {{ harness.testSuiteIds?.length || 0 }} suites
                    </span>
                    <span v-if="harness.team" class="stat">
                      <Users class="stat-icon" />
                      {{ harness.team }}
                    </span>
                  </div>
                </div>
                <div class="harness-actions">
                  <button @click="viewHarness(harness.id)" class="btn-secondary">
                    View Details
                  </button>
                  <button @click="removeHarness(harness.id)" class="btn-danger">
                    <Trash2 class="btn-icon-small" />
                    Remove
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Execution Results -->
        <div class="section-card">
          <div class="section-header">
            <FileText class="section-icon" />
            <h2 class="section-title">Recent Execution Results</h2>
          </div>
          <div class="empty-state">
            <Info class="empty-icon" />
            <p>Execution results will appear here after battery runs in CI/CD</p>
          </div>
        </div>

        <!-- Cross Links -->
        <CrossLinkPanel
          v-if="battery"
          entity-type="test-battery"
          :entity-id="battery.id"
        />
      </div>
    </div>

    <!-- Add Harness Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddHarnessModal" class="modal-overlay" @click="showAddHarnessModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Add Harness to Battery</h2>
              <button @click="showAddHarnessModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="loadingAvailableHarnesses" class="loading">Loading harnesses...</div>
              <div v-else-if="availableHarnesses.length === 0" class="empty-state">
                <p>No available harnesses. All harnesses are already in this battery.</p>
              </div>
              <div v-else class="harnesses-selection">
                <div
                  v-for="harness in availableHarnesses"
                  :key="harness.id"
                  class="harness-option"
                  @click="addHarness(harness.id)"
                >
                  <div class="harness-info">
                    <span class="harness-name">{{ harness.name }}</span>
                    <span v-if="harness.description" class="harness-description">
                      {{ harness.description }}
                    </span>
                    <span class="harness-meta">
                      {{ harness.testSuiteIds?.length || 0 }} suites
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Edit Battery Modal -->
    <TestBatteryModal
      :show="showEditModal"
      :editing-battery="battery"
      @close="showEditModal = false"
      @saved="handleBatteryUpdated"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { Teleport } from 'vue';
import {
  Battery,
  Layers,
  Settings,
  Edit,
  Trash2,
  ArrowLeft,
  Plus,
  X,
  Users,
  Clock,
  List,
  FileText,
  Info,
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import CrossLinkPanel from '../components/CrossLinkPanel.vue';
import TestBatteryModal from '../components/TestBatteryModal.vue';
import type { TestBattery } from '../../core/types';

const router = useRouter();
const route = useRoute();

const battery = ref<TestBattery | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);

const harnesses = ref<any[]>([]);
const loadingHarnesses = ref(false);
const harnessesError = ref<string | null>(null);

const showAddHarnessModal = ref(false);
const availableHarnesses = ref<any[]>([]);
const loadingAvailableHarnesses = ref(false);

const showEditModal = ref(false);

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests?tab=batteries' },
  { label: battery.value?.name || 'Battery' },
]);

const loadBattery = async () => {
  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/test-batteries/${route.params.id}`);
    battery.value = response.data;
    await loadHarnesses();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load test battery';
    console.error('Error loading battery:', err);
  } finally {
    loading.value = false;
  }
};

const loadHarnesses = async () => {
  if (!battery.value?.harnessIds || battery.value.harnessIds.length === 0) {
    harnesses.value = [];
    return;
  }

  loadingHarnesses.value = true;
  harnessesError.value = null;
  try {
    const promises = battery.value.harnessIds.map(async (harnessId) => {
      try {
        const response = await axios.get(`/api/test-harnesses/${harnessId}`);
        return response.data;
      } catch (err) {
        console.error(`Error loading harness ${harnessId}:`, err);
        return null;
      }
    });

    const results = await Promise.all(promises);
    harnesses.value = results.filter(h => h !== null);
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load harnesses';
    console.error('Error loading harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

const loadAvailableHarnesses = async () => {
  loadingAvailableHarnesses.value = true;
  try {
    const response = await axios.get('/api/test-harnesses');
    const allHarnesses = response.data || [];
    // Filter out harnesses already in the battery
    const currentHarnessIds = battery.value?.harnessIds || [];
    availableHarnesses.value = allHarnesses.filter(
      (h: any) => !currentHarnessIds.includes(h.id)
    );
  } catch (err) {
    console.error('Error loading available harnesses:', err);
    availableHarnesses.value = [];
  } finally {
    loadingAvailableHarnesses.value = false;
  }
};

const addHarness = async (harnessId: string) => {
  try {
    await axios.post(`/api/test-batteries/${route.params.id}/harnesses`, {
      harnessId,
    });
    showAddHarnessModal.value = false;
    await loadBattery();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to add harness');
  }
};

const removeHarness = async (harnessId: string) => {
  if (!confirm('Are you sure you want to remove this harness from the battery?')) {
    return;
  }

  try {
    await axios.delete(`/api/test-batteries/${route.params.id}/harnesses/${harnessId}`);
    await loadBattery();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to remove harness');
  }
};

const editBattery = () => {
  showEditModal.value = true;
};

const handleBatteryUpdated = async () => {
  showEditModal.value = false;
  await loadBattery();
};

const deleteBattery = async () => {
  if (!confirm('Are you sure you want to delete this test battery? This action cannot be undone.')) {
    return;
  }

  try {
    await axios.delete(`/api/test-batteries/${route.params.id}`);
    router.push({ path: '/tests', query: { tab: 'batteries' } });
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to delete battery');
  }
};

const viewHarness = (harnessId: string) => {
  router.push({ path: `/tests/harnesses/${harnessId}` });
};

const goBack = () => {
  router.push({ path: '/tests', query: { tab: 'batteries' } });
};

const formatDate = (date: Date | string | null): string => {
  if (!date) return 'Unknown';
  return new Date(date).toLocaleDateString();
};

// Watch for modal to load available harnesses
watch(showAddHarnessModal, (isShowing) => {
  if (isShowing) {
    loadAvailableHarnesses();
  }
});

onMounted(() => {
  loadBattery();
});
</script>


<style scoped>
.test-battery-detail-page {
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

.battery-description {
  color: #a0aec0;
  font-size: 1rem;
  margin: 0 0 1rem 0;
}

.battery-meta {
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

.config-details {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.config-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.config-label {
  font-weight: 500;
  color: #a0aec0;
}

.config-value {
  font-weight: 600;
  color: #ffffff;
}

.execution-mode.parallel {
  color: #22c55e;
}

.execution-mode.sequential {
  color: #4facfe;
}

.harnesses-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.harness-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1.25rem;
  transition: all 0.2s;
}

.harness-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
}

.harness-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.harness-info {
  flex: 1;
}

.harness-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.harness-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 0.75rem 0;
}

.harness-stats {
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

.stat-icon {
  width: 14px;
  height: 14px;
}

.harness-actions {
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

.harnesses-selection {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-height: 400px;
  overflow-y: auto;
}

.harness-option {
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.harness-option:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
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

