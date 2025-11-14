<template>
  <div class="test-harnesses-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Harnesses</h1>
          <p class="page-description">Collections of test suites assigned to applications</p>
        </div>
        <button @click="createHarness" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Harness
        </button>
      </div>
    </div>
    
    <div class="info-banner">
      <AlertCircle class="info-icon" />
      <p>Tests run automatically in CI/CD during builds. This UI is for viewing and managing test organization.</p>
    </div>
    
    <div v-if="loadingHarnesses" class="loading">Loading test harnesses...</div>
    <div v-if="harnessesError" class="error">{{ harnessesError }}</div>
    <div v-if="!loadingHarnesses && !harnessesError && testHarnesses.length === 0" class="empty-state">
      <Layers class="empty-icon" />
      <h3>No test harnesses found</h3>
      <p>Create a test harness to organize your test suites</p>
      <button @click="createHarness" class="btn-primary">
        Create Test Harness
      </button>
    </div>
    <div v-if="!loadingHarnesses && !harnessesError && testHarnesses.length > 0" class="harnesses-grid">
      <div
        v-for="harness in testHarnesses"
        :key="harness.id"
        class="harness-card"
      >
        <div class="harness-content" @click="viewHarness(harness.id)">
          <div class="harness-header">
            <h3 class="harness-name">{{ harness.name }}</h3>
            <div class="harness-badges">
              <span class="badge">{{ harness.testSuiteIds?.length || 0 }} suites</span>
              <span class="badge">{{ harness.applicationIds?.length || 0 }} applications</span>
            </div>
          </div>
          <p v-if="harness.description" class="harness-description">{{ harness.description }}</p>
          <div class="harness-meta">
            <span v-if="harness.team" class="team-badge">{{ harness.team }}</span>
          </div>
        </div>
        <div class="harness-actions" @click.stop>
          <button @click="editHarness(harness)" class="btn-icon" title="Edit">
            <Edit class="icon-small" />
          </button>
          <button @click="viewHarness(harness.id)" class="btn-icon" title="View Details">
            <FileText class="icon-small" />
          </button>
        </div>
      </div>
    </div>
    
    <!-- Test Harness Modal -->
    <TestHarnessModal
      :show="showHarnessModal"
      :editing-harness="editingHarness"
      @close="closeHarnessModal"
      @saved="handleHarnessSaved"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Layers, Plus, AlertCircle, Edit, FileText } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestHarnessModal from '../components/TestHarnessModal.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test Harnesses' }
];

const testHarnesses = ref<any[]>([]);
const loadingHarnesses = ref(false);
const harnessesError = ref<string | null>(null);
const showHarnessModal = ref(false);
const editingHarness = ref<any>(null);

const loadTestHarnesses = async () => {
  try {
    loadingHarnesses.value = true;
    harnessesError.value = null;
    const response = await axios.get('/api/test-harnesses');
    testHarnesses.value = response.data;
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load test harnesses';
    console.error('Error loading test harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

const createHarness = () => {
  editingHarness.value = null;
  showHarnessModal.value = true;
};

const editHarness = (harness: any) => {
  editingHarness.value = harness;
  showHarnessModal.value = true;
};

const handleHarnessSaved = async () => {
  await loadTestHarnesses();
};

const closeHarnessModal = () => {
  showHarnessModal.value = false;
  editingHarness.value = null;
};

const viewHarness = (id: string) => {
  router.push({ path: `/tests/harnesses/${id}` });
};

onMounted(() => {
  loadTestHarnesses();
});
</script>

<style scoped>
.test-harnesses-page {
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

.harnesses-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
}

.harness-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  transition: all 0.2s;
}

.harness-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.harness-content {
  flex: 1;
  cursor: pointer;
}

.harness-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.75rem;
  gap: 1rem;
}

.harness-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.harness-badges {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.badge {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
}

.harness-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 1rem 0;
}

.harness-meta {
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

.harness-actions {
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

