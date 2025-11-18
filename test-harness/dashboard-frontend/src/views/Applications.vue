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

    <div v-if="!loading && !error" class="applications-table-container">
      <table class="applications-table">
        <thead>
          <tr>
            <th>Application</th>
            <th>Status</th>
            <th>Owner / Team</th>
            <th>Last Battery Run</th>
            <th>Assigned Test Batteries</th>
            <th>Compliance Score</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="application in applications"
            :key="application.id"
            class="application-row"
            @click="viewApplication(application.id)"
          >
            <td>
              <div class="app-name-cell">
                <strong>{{ application.name }}</strong>
                <span v-if="application.description" class="app-description">{{ application.description }}</span>
              </div>
            </td>
            <td>
              <span class="status-badge" :class="getStatusClass(application)">
                {{ getStatus(application) }}
              </span>
            </td>
            <td>
              <div class="owner-cell">
                <span v-if="application.owner" class="owner">{{ application.owner }}</span>
                <span v-if="application.team" class="team">{{ application.team }}</span>
              </div>
            </td>
            <td>
              <span v-if="application.lastBatteryRun" class="last-run">
                {{ formatTime(application.lastBatteryRun) }}
              </span>
              <span v-else class="never-run">Never</span>
            </td>
            <td>
              <div v-if="application.testBatteries && application.testBatteries.length > 0" class="batteries-list">
                <span
                  v-for="battery in application.testBatteries"
                  :key="battery.id"
                  class="battery-tag clickable"
                  @click.stop="viewBattery(battery.id)"
                  :title="`View ${battery.name} details`"
                >
                  {{ battery.name }}
                </span>
              </div>
              <span v-else class="no-assignments">None</span>
            </td>
            <td>
              <span class="compliance-score" :class="getScoreClass(application.complianceScore || 0)">
                {{ application.complianceScore || 0 }}%
              </span>
            </td>
            <td>
              <div class="actions-cell" @click.stop>
                <button
                  @click="viewApplication(application.id)"
                  class="btn-link"
                  title="View Details"
                >
                  View
                </button>
                <button
                  @click="manageAssignments(application.id)"
                  class="btn-link"
                  title="Manage Assignments"
                >
                  Manage Assignments
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="applications.length === 0" class="empty-state">
        <p>No applications found</p>
      </div>
    </div>

    <!-- Assignment Manager Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAssignmentManager && selectedApplicationId" class="modal-overlay" @click="showAssignmentManager = false">
          <div class="modal-content-large" @click.stop>
            <div class="modal-header">
              <h2>Manage Assignments</h2>
              <button @click="showAssignmentManager = false" class="modal-close">
                <span class="close-icon">×</span>
              </button>
            </div>
            <div class="modal-body">
              <AssignmentManager
                :application-id="selectedApplicationId"
                @updated="handleAssignmentUpdated"
              />
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Teleport, Transition } from 'vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import AssignmentManager from '../components/AssignmentManager.vue';

const router = useRouter();
const loading = ref(true);
const error = ref<string | null>(null);
const applications = ref<any[]>([]);
const showAssignmentManager = ref(false);
const selectedApplicationId = ref<string | null>(null);

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Applications', to: '/applications' },
];

const fetchApplications = async () => {
  try {
    loading.value = true;
    error.value = null;
    
    // Fetch applications
    const appsResponse = await fetch('/api/v1/applications');
    if (!appsResponse.ok) throw new Error('Failed to fetch applications');
    const appsData = await appsResponse.json();
    
    // For each application, fetch assigned harnesses and batteries
    const appsWithAssignments = await Promise.all(
      appsData.map(async (app: any) => {
        try {
          // Fetch test harnesses for this application using the new endpoint
          const harnessesResponse = await fetch(`/api/v1/applications/${app.id}/test-harnesses`);
          const harnesses = harnessesResponse.ok ? await harnessesResponse.json() : [];
          
          // Fetch test batteries for this application using the new endpoint
          const batteriesResponse = await fetch(`/api/v1/applications/${app.id}/test-batteries`);
          const batteries = batteriesResponse.ok ? await batteriesResponse.json() : [];
          
          // Fetch last battery run
          let lastBatteryRun = null;
          if (batteries.length > 0) {
            try {
              const runsResponse = await fetch(`/api/v1/applications/${app.id}/runs?limit=1`);
              if (runsResponse.ok) {
                const runs = await runsResponse.json();
                if (runs.length > 0) {
                  lastBatteryRun = runs[0].timestamp || runs[0].createdAt;
                }
              }
            } catch (err) {
              console.error(`Error loading runs for application ${app.id}:`, err);
            }
          }
          
          return {
            ...app,
            testHarnesses: harnesses,
            testBatteries: batteries,
            testSuiteCount: harnesses.reduce((sum: number, h: any) => sum + (h.testSuiteIds?.length || 0), 0),
            lastBatteryRun,
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
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const getStatus = (application: any): string => {
  const score = application.complianceScore || 0;
  const lastRun = application.lastBatteryRun;
  
  if (!lastRun) return 'Never Tested';
  if (score >= 90) return 'Pass';
  if (score >= 70) return 'Degraded';
  return 'Fail';
};

const getStatusClass = (application: any): string => {
  const status = getStatus(application);
  if (status === 'Pass') return 'status-pass';
  if (status === 'Degraded') return 'status-degraded';
  if (status === 'Fail') return 'status-fail';
  return 'status-never';
};

const formatTime = (date: string | Date | null): string => {
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

const viewApplication = (id: string) => {
  router.push({ name: 'ApplicationDetail', params: { id } });
};

const manageAssignments = (id: string) => {
  selectedApplicationId.value = id;
  showAssignmentManager.value = true;
};

const handleAssignmentUpdated = () => {
  fetchApplications();
};

const viewBattery = (id: string) => {
  router.push({ path: `/tests/batteries/${id}` });
};

const viewHarness = (id: string) => {
  router.push({ path: `/tests/harnesses/${id}` });
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

.applications-table-container {
  overflow-x: auto;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.applications-table {
  width: 100%;
  border-collapse: collapse;
}

.applications-table th {
  text-align: left;
  padding: 12px 16px;
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  white-space: nowrap;
}

.applications-table td {
  padding: 16px;
  color: #ffffff;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.application-row {
  cursor: pointer;
  transition: background 0.2s;
}

.application-row:hover {
  background: rgba(79, 172, 254, 0.05);
}

.app-name-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.app-name-cell strong {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
}

.app-description {
  font-size: 0.875rem;
  color: #a0aec0;
}

.status-badge {
  padding: 6px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
  display: inline-block;
}

.status-pass {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-degraded {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-fail {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-never {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.owner-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.owner {
  font-size: 0.875rem;
  color: #ffffff;
}

.team {
  font-size: 0.75rem;
  color: #a0aec0;
}

.last-run {
  font-size: 0.875rem;
  color: #ffffff;
}

.never-run {
  font-size: 0.875rem;
  color: #a0aec0;
  font-style: italic;
}

.batteries-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.battery-tag {
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  font-size: 0.75rem;
  color: #4facfe;
}

.battery-tag.clickable {
  cursor: pointer;
  transition: all 0.2s;
}

.battery-tag.clickable:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.no-assignments {
  font-size: 0.875rem;
  color: #a0aec0;
  font-style: italic;
}

.compliance-score {
  font-size: 0.875rem;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 6px;
  display: inline-block;
}

.compliance-score.score-high {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.compliance-score.score-medium {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.compliance-score.score-low {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.actions-cell {
  display: flex;
  gap: 8px;
}

.btn-link {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.btn-link:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
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

.modal-content-large {
  background: #1a1f2e;
  border-radius: 16px;
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
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
  font-size: 1.5rem;
  line-height: 1;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  display: block;
}

.modal-body {
  padding: 2rem;
  overflow-y: auto;
  flex: 1;
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

