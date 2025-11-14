<template>
  <div class="test-batteries-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Batteries</h1>
          <p class="page-description">Collections of test harnesses that can be executed together</p>
        </div>
        <button @click="createBattery" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Battery
        </button>
      </div>
    </div>
    
    <div class="info-banner">
      <AlertCircle class="info-icon" />
      <p>Tests run automatically in CI/CD during builds. This UI is for viewing and managing test organization.</p>
    </div>
    
    <div v-if="loadingBatteries" class="loading">Loading test batteries...</div>
    <div v-if="batteriesError" class="error">{{ batteriesError }}</div>
    <div v-if="!loadingBatteries && !batteriesError && testBatteries.length === 0" class="empty-state">
      <Battery class="empty-icon" />
      <h3>No test batteries found</h3>
      <p>Create a test battery to organize your test harnesses</p>
      <button @click="createBattery" class="btn-primary">
        Create Test Battery
      </button>
    </div>
    <div v-if="!loadingBatteries && !batteriesError && testBatteries.length > 0" class="batteries-grid">
      <div
        v-for="battery in testBatteries"
        :key="battery.id"
        class="battery-card"
      >
        <div class="battery-content" @click="viewBattery(battery.id)">
          <div class="battery-header">
            <h3 class="battery-name">{{ battery.name }}</h3>
            <span class="battery-badge">{{ battery.harnessIds?.length || 0 }} harnesses</span>
          </div>
          <p v-if="battery.description" class="battery-description">{{ battery.description }}</p>
          <div class="battery-meta">
            <span v-if="battery.team" class="team-badge">{{ battery.team }}</span>
            <span class="execution-mode">{{ battery.executionConfig?.executionMode || 'sequential' }}</span>
          </div>
        </div>
        <div class="battery-actions" @click.stop>
          <button @click="editBattery(battery)" class="btn-icon" title="Edit">
            <Edit class="icon-small" />
          </button>
          <button @click="viewBattery(battery.id)" class="btn-icon" title="View Details">
            <FileText class="icon-small" />
          </button>
        </div>
      </div>
    </div>
    
    <!-- Test Battery Modal -->
    <TestBatteryModal
      :show="showBatteryModal"
      :editing-battery="editingBattery"
      @close="closeBatteryModal"
      @saved="handleBatterySaved"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Battery, Plus, AlertCircle, Edit, FileText } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestBatteryModal from '../components/TestBatteryModal.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test Batteries' }
];

const testBatteries = ref<any[]>([]);
const loadingBatteries = ref(false);
const batteriesError = ref<string | null>(null);
const showBatteryModal = ref(false);
const editingBattery = ref<any>(null);

const loadTestBatteries = async () => {
  try {
    loadingBatteries.value = true;
    batteriesError.value = null;
    const response = await axios.get('/api/test-batteries');
    testBatteries.value = response.data;
  } catch (err: any) {
    batteriesError.value = err.response?.data?.message || 'Failed to load test batteries';
    console.error('Error loading test batteries:', err);
  } finally {
    loadingBatteries.value = false;
  }
};

const createBattery = () => {
  editingBattery.value = null;
  showBatteryModal.value = true;
};

const editBattery = (battery: any) => {
  editingBattery.value = battery;
  showBatteryModal.value = true;
};

const handleBatterySaved = async () => {
  await loadTestBatteries();
};

const closeBatteryModal = () => {
  showBatteryModal.value = false;
  editingBattery.value = null;
};

const viewBattery = (id: string) => {
  router.push({ path: `/tests/batteries/${id}` });
};

onMounted(() => {
  loadTestBatteries();
});
</script>

<style scoped>
.test-batteries-page {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.info-banner {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  margin-bottom: 2rem;
}

.info-banner .info-icon {
  color: #4facfe;
  flex-shrink: 0;
}

.info-banner p {
  margin: 0;
  color: #a0aec0;
  font-size: 0.875rem;
}

.loading, .error {
  padding: 2rem;
  text-align: center;
}

.error {
  color: #fc8181;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 1rem;
  opacity: 0.5;
}

.empty-state h3 {
  color: #ffffff;
  margin-bottom: 0.5rem;
}

.empty-state p {
  color: #a0aec0;
  margin-bottom: 1.5rem;
}

.batteries-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
}

.battery-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  transition: all 0.2s;
}

.battery-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.battery-content {
  flex: 1;
  cursor: pointer;
}

.battery-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.75rem;
}

.battery-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.battery-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
}

.battery-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 1rem 0;
}

.battery-meta {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.team-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(139, 92, 246, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #a78bfa;
}

.execution-mode {
  padding: 0.25rem 0.75rem;
  background: rgba(0, 242, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #00f2fe;
  text-transform: capitalize;
}

.battery-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-icon {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  padding: 0.5rem;
  cursor: pointer;
  color: #4facfe;
  transition: all 0.2s;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.icon-small {
  width: 16px;
  height: 16px;
}
</style>

