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
        <div v-if="assignmentModal.isOpen.value && assignmentModal.data.value" class="modal-overlay" @click="assignmentModal.close()">
          <div class="modal-content-large" @click.stop>
            <div class="modal-header">
              <h2>Manage Assignments</h2>
              <button @click="assignmentModal.close()" class="modal-close">
                <span class="close-icon">×</span>
              </button>
            </div>
            <div class="modal-body">
              <AssignmentManager
                :application-id="assignmentModal.data.value"
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
import { useRouter } from 'vue-router';
import { Teleport, Transition } from 'vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import AssignmentManager from '../components/AssignmentManager.vue';
import { useApiDataAuto } from '../composables/useApiData';
import { useModal } from '../composables/useModal';
import type { Application } from '../types/test';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Applications', to: '/applications' },
];

// Use composable for API data fetching
const { data: applications, loading, error, reload } = useApiDataAuto(
  async () => {
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
            testSuiteCount: harnesses.reduce((sum: number, h) => sum + (h.testSuiteIds?.length || 0), 0),
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
    
    return appsWithAssignments;
  },
  {
    initialData: [],
    errorMessage: 'Failed to load applications',
  }
);

// Use composable for modal state management
const assignmentModal = useModal<string>();

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

const getStatusClass = (application: Application): string => {
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
  assignmentModal.open(id);
};

const handleAssignmentUpdated = () => {
  reload();
};

const viewBattery = (id: string) => {
  router.push({ path: `/tests/batteries/${id}` });
};

const viewHarness = (id: string) => {
  router.push({ path: `/tests/harnesses/${id}` });
};
</script>

<style scoped>
.applications-page {
  padding: 2rem;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  color: var(--color-text-secondary);
  margin: 0;
}

.loading, .error {
  padding: var(--spacing-xl);
  text-align: center;
}

.error {
  color: var(--color-error-dark);
}

.applications-table-container {
  overflow-x: auto;
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.applications-table {
  width: 100%;
  border-collapse: collapse;
}

.applications-table th {
  text-align: left;
  padding: var(--spacing-sm) var(--spacing-md);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-secondary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  white-space: nowrap;
}

.applications-table td {
  padding: var(--spacing-md);
  color: var(--color-text-primary);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.application-row {
  cursor: pointer;
  transition: var(--transition-base);
}

.application-row:hover {
  background: var(--border-color-muted);
  opacity: 0.5;
}

.app-name-cell {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.app-name-cell strong {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.app-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
  display: inline-block;
}

.status-pass {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-degraded {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-fail {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-never {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
}

.owner-cell {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.owner {
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.team {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.last-run {
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.never-run {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  font-style: italic;
}

.batteries-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
}

.battery-tag {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  color: var(--color-primary);
}

.battery-tag.clickable {
  cursor: pointer;
  transition: var(--transition-all);
}

.battery-tag.clickable:hover {
  background: var(--border-color-primary);
  border-color: var(--border-color-primary-hover);
}

.no-assignments {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  font-style: italic;
}

.compliance-score {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  display: inline-block;
}

.compliance-score.score-high {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.compliance-score.score-medium {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.compliance-score.score-low {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.actions-cell {
  display: flex;
  gap: var(--spacing-sm);
}

.btn-link {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.btn-link:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-tertiary);
  border: var(--border-width-thin) solid var(--border-color-muted);
  border-radius: var(--border-radius-xs);
  cursor: pointer;
  font-size: var(--font-size-sm);
}

.btn-secondary:hover {
  background: var(--color-bg-card);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-index-modal);
  padding: var(--spacing-xl);
}

.modal-content-large {
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: var(--shadow-xl);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-lg) var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header h2 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.modal-close {
  background: transparent;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  padding: var(--spacing-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--border-radius-xs);
  transition: var(--transition-all);
  font-size: var(--font-size-2xl);
  line-height: 1;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  display: block;
}

.modal-body {
  padding: var(--spacing-xl);
  overflow-y: auto;
  flex: 1;
}

.fade-enter-active,
.fade-leave-active {
  transition: var(--transition-slow);
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

