<template>
  <div class="applications-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Applications</h1>
          <p class="page-description">View applications and their assigned test harnesses and batteries</p>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading applications...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error" class="applications-list">
      <div
        v-for="application in applications"
        :key="application.id"
        class="application-card"
      >
        <div class="application-header">
          <h3 class="application-name">{{ application.name }}</h3>
          <div class="application-meta">
            <span class="team-badge">{{ application.team }}</span>
            <span class="compliance-score" :class="getScoreClass(application.complianceScore)">
              {{ application.complianceScore }}% Compliant
            </span>
          </div>
        </div>

        <div class="application-content">
          <div class="info-section">
            <h4>Assigned Test Batteries</h4>
            <div v-if="application.testBatteries && application.testBatteries.length > 0" class="items-list">
              <span
                v-for="battery in application.testBatteries"
                :key="battery.id"
                class="item-tag"
              >
                {{ battery.name }}
              </span>
            </div>
            <div v-else class="empty-state">No test batteries assigned</div>
          </div>

          <div class="info-section">
            <h4>Assigned Test Harnesses</h4>
            <div v-if="application.testHarnesses && application.testHarnesses.length > 0" class="items-list">
              <span
                v-for="harness in application.testHarnesses"
                :key="harness.id"
                class="item-tag"
              >
                {{ harness.name }}
              </span>
            </div>
            <div v-else class="empty-state">No test harnesses assigned</div>
          </div>

          <div class="info-section">
            <h4>Test Suites</h4>
            <div class="stat-row">
              <span>Total Suites:</span>
              <strong>{{ application.testSuiteCount || 0 }}</strong>
            </div>
          </div>

          <div class="info-section">
            <h4>Status</h4>
            <div class="stat-row">
              <span>Last Test Run:</span>
              <span>{{ formatDate(application.lastTestRun) || 'Never' }}</span>
            </div>
            <div class="stat-row">
              <span>Findings:</span>
              <strong :class="getFindingsClass(application.findingsCount)">
                {{ application.findingsCount || 0 }}
              </strong>
            </div>
          </div>
        </div>

        <div class="application-actions">
          <button
            @click="viewApplication(application.id)"
            class="btn-secondary"
          >
            View Details
          </button>
          <button
            @click="manageAssignments(application.id)"
            class="btn-secondary"
          >
            Manage Assignments
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import Breadcrumb from '../components/Breadcrumb.vue';

const router = useRouter();
const loading = ref(true);
const error = ref<string | null>(null);
const applications = ref<any[]>([]);

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Applications', to: '/applications' },
];

const fetchApplications = async () => {
  try {
    loading.value = true;
    error.value = null;
    
    // Fetch applications
    const appsResponse = await fetch('/api/applications');
    if (!appsResponse.ok) throw new Error('Failed to fetch applications');
    const appsData = await appsResponse.json();
    
    // For each application, fetch assigned harnesses and batteries
    const appsWithAssignments = await Promise.all(
      appsData.map(async (app: any) => {
        try {
          // Fetch test harnesses for this application using the new endpoint
          const harnessesResponse = await fetch(`/api/applications/${app.id}/test-harnesses`);
          const harnesses = harnessesResponse.ok ? await harnessesResponse.json() : [];
          
          // Fetch test batteries for this application using the new endpoint
          const batteriesResponse = await fetch(`/api/applications/${app.id}/test-batteries`);
          const batteries = batteriesResponse.ok ? await batteriesResponse.json() : [];
          
          return {
            ...app,
            testHarnesses: harnesses,
            testBatteries: batteries,
            testSuiteCount: harnesses.reduce((sum: number, h: any) => sum + (h.testSuiteIds?.length || 0), 0),
          };
        } catch (err) {
          console.error(`Error loading assignments for application ${app.id}:`, err);
          return {
            ...app,
            testHarnesses: [],
            testBatteries: [],
            testSuiteCount: 0,
          };
        }
      })
    );
    
    applications.value = appsWithAssignments;
  } catch (err: any) {
    error.value = err.message || 'Failed to load applications';
    console.error('Error fetching applications:', err);
  } finally {
    loading.value = false;
  }
};

const getScoreClass = (score: number) => {
  if (score >= 90) return 'high';
  if (score >= 70) return 'medium';
  return 'low';
};

const getFindingsClass = (count: number) => {
  if (count === 0) return 'no-findings';
  if (count < 10) return 'low-findings';
  return 'high-findings';
};

const formatDate = (date: string | Date | null) => {
  if (!date) return null;
  return new Date(date).toLocaleDateString();
};

const viewApplication = (id: string) => {
  router.push({ name: 'ApplicationDetail', params: { id } });
};

const manageAssignments = (id: string) => {
  // Navigate to assignment management (to be implemented)
  router.push({ path: `/applications/${id}/assignments` });
};

onMounted(() => {
  fetchApplications();
});
</script>

<style scoped>
.applications-page {
  padding: 2rem;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin: 0.5rem 0;
}

.page-description {
  color: #666;
  margin: 0;
}

.loading, .error {
  padding: 2rem;
  text-align: center;
}

.error {
  color: #d32f2f;
}

.applications-list {
  display: grid;
  gap: 1.5rem;
}

.application-card {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  background: white;
}

.application-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid #e0e0e0;
}

.application-name {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
}

.application-meta {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.team-badge {
  padding: 0.25rem 0.75rem;
  background: #f5f5f5;
  border-radius: 4px;
  font-size: 0.875rem;
}

.compliance-score {
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 600;
}

.compliance-score.high {
  background: #e8f5e9;
  color: #2e7d32;
}

.compliance-score.medium {
  background: #fff3e0;
  color: #f57c00;
}

.compliance-score.low {
  background: #ffebee;
  color: #c62828;
}

.application-content {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1.5rem;
  margin-bottom: 1rem;
}

.info-section h4 {
  font-size: 0.875rem;
  font-weight: 600;
  margin: 0 0 0.5rem 0;
  color: #666;
}

.items-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.item-tag {
  padding: 0.25rem 0.75rem;
  background: #e3f2fd;
  border-radius: 4px;
  font-size: 0.875rem;
}

.empty-state {
  color: #999;
  font-size: 0.875rem;
  font-style: italic;
}

.stat-row {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem 0;
  font-size: 0.875rem;
}

.stat-row strong {
  font-weight: 600;
}

.stat-row .no-findings {
  color: #2e7d32;
}

.stat-row .low-findings {
  color: #f57c00;
}

.stat-row .high-findings {
  color: #c62828;
}

.application-actions {
  display: flex;
  gap: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #e0e0e0;
}

.btn-secondary {
  padding: 0.5rem 1rem;
  background: #f5f5f5;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.875rem;
}

.btn-secondary:hover {
  background: #e0e0e0;
}
</style>

