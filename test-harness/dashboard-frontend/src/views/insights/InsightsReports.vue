<template>
  <div class="insights-reports-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Reports</h1>
          <p class="page-description">Compliance snapshots and saved reports</p>
        </div>
        <button @click="createSnapshot" class="btn-primary" :disabled="creatingSnapshot">
          <Plus class="btn-icon" />
          {{ creatingSnapshot ? 'Creating...' : 'Create Snapshot' }}
        </button>
      </div>
    </div>

    <!-- Compliance Snapshots Section -->
    <div class="reports-section">
      <div class="section-header">
        <h2 class="section-title">Compliance Snapshots</h2>
      </div>
      
      <div v-if="snapshotsLoading" class="loading-state">
        <p>Loading snapshots...</p>
      </div>
      <div v-else-if="snapshotsError" class="error-state">
        <p>{{ snapshotsError }}</p>
      </div>
      <div v-else-if="snapshots.length === 0" class="empty-state">
        <p>No compliance snapshots yet</p>
        <p class="empty-description">Create a snapshot to capture the current compliance state</p>
      </div>
      <div v-else class="snapshots-list">
        <div
          v-for="snapshot in snapshots"
          :key="snapshot.id"
          class="snapshot-card"
          @click="viewSnapshot(snapshot.id)"
        >
          <div class="snapshot-header">
            <h3 class="snapshot-name">{{ snapshot.name }}</h3>
            <span class="snapshot-score" :class="getScoreClass(snapshot.overallScore)">
              {{ snapshot.overallScore }}%
            </span>
          </div>
          <div class="snapshot-meta">
            <span>{{ formatTime(snapshot.timestamp) }}</span>
            <span>{{ snapshot.applications.length }} application{{ snapshot.applications.length !== 1 ? 's' : '' }}</span>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Saved Reports Section -->
    <div class="reports-section" style="margin-top: 32px;">
      <h2 class="section-title">Saved Reports</h2>
      <Reports />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Plus } from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../../components/Breadcrumb.vue';
import Reports from '../Reports.vue';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights & Reports', to: '/insights' },
  { label: 'Reports' }
];

const snapshots = ref<any[]>([]);
const snapshotsLoading = ref(false);
const snapshotsError = ref<string | null>(null);
const creatingSnapshot = ref(false);

const loadSnapshots = async () => {
  try {
    snapshotsLoading.value = true;
    snapshotsError.value = null;
    const response = await axios.get('/api/v1/compliance-snapshots', {
      params: { limit: 20 }
    });
    snapshots.value = response.data || [];
  } catch (err: any) {
    snapshotsError.value = err.response?.data?.message || 'Failed to load snapshots';
    console.error('Error loading snapshots:', err);
  } finally {
    snapshotsLoading.value = false;
  }
};

const createSnapshot = async () => {
  try {
    creatingSnapshot.value = true;
    await axios.post('/api/v1/compliance-snapshots', {
      name: `Snapshot ${new Date().toLocaleString()}`
    });
    await loadSnapshots();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to create snapshot');
    console.error('Error creating snapshot:', err);
  } finally {
    creatingSnapshot.value = false;
  }
};

const viewSnapshot = (id: string) => {
  router.push(`/insights/reports?snapshotId=${id}`);
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const formatTime = (date: Date | string | null): string => {
  if (!date) return 'Never';
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
};

onMounted(() => {
  loadSnapshots();
});
</script>

<style scoped>
.insights-reports-page {
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
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
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
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.reports-section {
  margin-bottom: 32px;
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

.snapshots-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}

.snapshot-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.2s;
}

.snapshot-card:hover {
  transform: translateY(-2px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.2);
}

.snapshot-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.snapshot-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.snapshot-score {
  font-size: 1.25rem;
  font-weight: 700;
}

.score-high {
  color: #22c55e;
}

.score-medium {
  color: #fbbf24;
}

.score-low {
  color: #fc8181;
}

.snapshot-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: 60px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  color: #a0aec0;
}

.empty-description {
  margin-top: 8px;
  font-size: 0.9rem;
}
</style>
