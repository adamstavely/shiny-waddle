<template>
  <div class="assignment-manager">
    <div class="manager-header">
      <h3 class="manager-title">
        <Package class="title-icon" />
        Test Assignments
      </h3>
      <p class="manager-description">
        Manage test harnesses and batteries assigned to this application
      </p>
    </div>

    <!-- Test Harnesses Section -->
    <div class="assignment-section">
      <div class="section-header">
        <Layers class="section-icon" />
        <h4 class="section-title">Test Harnesses</h4>
        <button @click="showAddHarnessModal = true" class="btn-add">
          <Plus class="btn-icon" />
          Assign Harness
        </button>
      </div>
      <div v-if="loadingHarnesses" class="loading">Loading harnesses...</div>
      <div v-else-if="harnessesError" class="error">{{ harnessesError }}</div>
      <div v-else-if="assignedHarnesses.length === 0" class="empty-state">
        <Layers class="empty-icon" />
        <p>No harnesses assigned</p>
        <button @click="showAddHarnessModal = true" class="btn-primary-small">
          Assign Harness
        </button>
      </div>
      <div v-else class="assignments-list">
        <div
          v-for="harness in assignedHarnesses"
          :key="harness.id"
          class="assignment-item"
        >
          <div class="item-info">
            <h5 class="item-name">{{ harness.name }}</h5>
            <p v-if="harness.description" class="item-description">{{ harness.description }}</p>
            <div class="item-meta">
              <span class="meta-badge">
                <List class="meta-icon" />
                {{ harness.testSuiteIds?.length || 0 }} suites
              </span>
              <span v-if="harness.team" class="meta-badge">
                <Users class="meta-icon" />
                {{ harness.team }}
              </span>
            </div>
          </div>
          <div class="item-actions">
            <button @click="viewHarness(harness.id)" class="btn-secondary-small">
              View
            </button>
            <button @click="unassignHarness(harness.id)" class="btn-danger-small">
              <Trash2 class="btn-icon-small" />
              Unassign
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Batteries Section -->
    <div class="assignment-section">
      <div class="section-header">
        <Battery class="section-icon" />
        <h4 class="section-title">Test Batteries</h4>
        <span class="section-note">(via assigned harnesses)</span>
      </div>
      <div v-if="loadingBatteries" class="loading">Loading batteries...</div>
      <div v-else-if="batteriesError" class="error">{{ batteriesError }}</div>
      <div v-else-if="assignedBatteries.length === 0" class="empty-state">
        <Battery class="empty-icon" />
        <p>No batteries assigned (assign harnesses to see batteries)</p>
      </div>
      <div v-else class="assignments-list">
        <div
          v-for="battery in assignedBatteries"
          :key="battery.id"
          class="assignment-item"
        >
          <div class="item-info">
            <h5 class="item-name">{{ battery.name }}</h5>
            <p v-if="battery.description" class="item-description">{{ battery.description }}</p>
            <div class="item-meta">
              <span class="meta-badge">
                <Layers class="meta-icon" />
                {{ battery.harnessIds?.length || 0 }} harnesses
              </span>
              <span class="meta-badge execution-mode" :class="battery.executionConfig?.executionMode || 'sequential'">
                {{ battery.executionConfig?.executionMode || 'sequential' }}
              </span>
            </div>
          </div>
          <div class="item-actions">
            <button @click="viewBattery(battery.id)" class="btn-secondary-small">
              View
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Add Harness Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddHarnessModal" class="modal-overlay" @click="showAddHarnessModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Assign Test Harness</h2>
              <button @click="showAddHarnessModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="loadingAvailableHarnesses" class="loading">Loading harnesses...</div>
              <div v-else-if="availableHarnesses.length === 0" class="empty-state">
                <p>No available harnesses. All harnesses are already assigned to this application.</p>
              </div>
              <div v-else class="selection-list">
                <div
                  v-for="harness in availableHarnesses"
                  :key="harness.id"
                  class="selection-option"
                  @click="assignHarness(harness.id)"
                >
                  <div class="option-info">
                    <span class="option-name">{{ harness.name }}</span>
                    <span v-if="harness.description" class="option-description">
                      {{ harness.description }}
                    </span>
                    <span class="option-meta">
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
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useRouter } from 'vue-router';
import { Teleport } from 'vue';
import {
  Package,
  Layers,
  Battery,
  Plus,
  Trash2,
  X,
  List,
  Users,
} from 'lucide-vue-next';
import axios from 'axios';

const props = defineProps<{
  applicationId: string;
}>();

const emit = defineEmits<{
  (e: 'updated'): void;
}>();

const router = useRouter();

const assignedHarnesses = ref<any[]>([]);
const loadingHarnesses = ref(false);
const harnessesError = ref<string | null>(null);

const assignedBatteries = ref<any[]>([]);
const loadingBatteries = ref(false);
const batteriesError = ref<string | null>(null);

const showAddHarnessModal = ref(false);
const availableHarnesses = ref<any[]>([]);
const loadingAvailableHarnesses = ref(false);

const loadAssignments = async () => {
  await Promise.all([loadHarnesses(), loadBatteries()]);
};

const loadHarnesses = async () => {
  loadingHarnesses.value = true;
  harnessesError.value = null;
  try {
    const response = await axios.get(`/api/v1/applications/${props.applicationId}/test-harnesses`);
    assignedHarnesses.value = response.data || [];
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load test harnesses';
    console.error('Error loading harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

const loadBatteries = async () => {
  loadingBatteries.value = true;
  batteriesError.value = null;
  try {
    const response = await axios.get(`/api/v1/applications/${props.applicationId}/test-batteries`);
    assignedBatteries.value = response.data || [];
  } catch (err: any) {
    batteriesError.value = err.response?.data?.message || 'Failed to load test batteries';
    console.error('Error loading batteries:', err);
  } finally {
    loadingBatteries.value = false;
  }
};

const loadAvailableHarnesses = async () => {
  loadingAvailableHarnesses.value = true;
  try {
    const response = await axios.get('/api/v1/test-harnesses');
    const allHarnesses = response.data || [];
    const assignedHarnessIds = assignedHarnesses.value.map(h => h.id);
    availableHarnesses.value = allHarnesses.filter(
      (h: any) => !assignedHarnessIds.includes(h.id)
    );
  } catch (err) {
    console.error('Error loading available harnesses:', err);
    availableHarnesses.value = [];
  } finally {
    loadingAvailableHarnesses.value = false;
  }
};

const assignHarness = async (harnessId: string) => {
  try {
    await axios.post(`/api/v1/test-harnesses/${harnessId}/applications`, {
      applicationId: props.applicationId,
    });
    showAddHarnessModal.value = false;
    await loadAssignments();
    emit('updated');
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to assign harness');
  }
};

const unassignHarness = async (harnessId: string) => {
  if (!confirm('Are you sure you want to unassign this harness from the application?')) {
    return;
  }

  try {
    await axios.delete(`/api/v1/test-harnesses/${harnessId}/applications/${props.applicationId}`);
    await loadAssignments();
    emit('updated');
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to unassign harness');
  }
};

const viewHarness = (harnessId: string) => {
  router.push({ path: `/tests/harnesses/${harnessId}` });
};

const viewBattery = (batteryId: string) => {
  router.push({ path: `/tests/batteries/${batteryId}` });
};

watch(showAddHarnessModal, (isShowing) => {
  if (isShowing) {
    loadAvailableHarnesses();
  }
});

onMounted(() => {
  loadAssignments();
});
</script>

<style scoped>
.assignment-manager {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.manager-header {
  margin-bottom: 2rem;
}

.manager-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.title-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.manager-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0;
}

.assignment-section {
  margin-bottom: 2rem;
}

.assignment-section:last-child {
  margin-bottom: 0;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.section-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
}

.section-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.section-note {
  font-size: 0.75rem;
  color: #718096;
  font-style: italic;
}

.btn-add {
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

.btn-add:hover {
  background: rgba(79, 172, 254, 0.2);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.loading,
.error {
  padding: 2rem;
  text-align: center;
  color: #718096;
}

.error {
  color: #fc8181;
}

.empty-state {
  padding: 2rem;
  text-align: center;
  color: #718096;
}

.empty-icon {
  width: 40px;
  height: 40px;
  color: #4facfe;
  margin: 0 auto 1rem;
  opacity: 0.5;
}

.empty-state p {
  margin: 0 0 1rem 0;
}

.btn-primary-small {
  padding: 0.5rem 1rem;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 6px;
  color: #0f1419;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary-small:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.assignments-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.assignment-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  padding: 1rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  transition: all 0.2s;
}

.assignment-item:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
}

.item-info {
  flex: 1;
}

.item-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.item-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 0.75rem 0;
}

.item-meta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.meta-badge {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 4px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.meta-badge.execution-mode.parallel {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.meta-badge.execution-mode.sequential {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.meta-icon {
  width: 12px;
  height: 12px;
}

.item-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-secondary-small,
.btn-danger-small {
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

.btn-secondary-small {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary-small:hover {
  background: rgba(79, 172, 254, 0.2);
}

.btn-danger-small {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.btn-danger-small:hover {
  background: rgba(252, 129, 129, 0.2);
}

.btn-icon-small {
  width: 14px;
  height: 14px;
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

.option-description {
  font-size: 0.75rem;
  color: #a0aec0;
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

