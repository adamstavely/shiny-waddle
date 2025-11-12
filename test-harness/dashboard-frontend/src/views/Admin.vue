<template>
  <div class="admin-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Admin</h1>
          <p class="page-description">Manage Sentinel configuration and registered applications</p>
        </div>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id as any"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
      </button>
    </div>

    <!-- Overview Tab -->
    <div v-if="activeTab === 'overview'" class="tab-content">
      <div class="overview-grid">
        <!-- Statistics Cards -->
        <div class="stat-card">
          <div class="stat-header">
            <Server class="stat-icon" />
            <h3 class="stat-title">Applications</h3>
          </div>
          <div class="stat-value">{{ applications.length }}</div>
          <div class="stat-label">Registered</div>
          <div class="stat-detail">
            <span class="stat-detail-item">
              <span class="detail-value">{{ activeApplications }}</span>
              <span class="detail-label">Active</span>
            </span>
            <span class="stat-detail-item">
              <span class="detail-value">{{ inactiveApplications }}</span>
              <span class="detail-label">Inactive</span>
            </span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-header">
            <TestTube class="stat-icon" />
            <h3 class="stat-title">Tests</h3>
          </div>
          <div class="stat-value">{{ totalTests }}</div>
          <div class="stat-label">Total Executed</div>
          <div class="stat-detail">
            <span class="stat-detail-item">
              <span class="detail-value">{{ passedTests }}</span>
              <span class="detail-label">Passed</span>
            </span>
            <span class="stat-detail-item">
              <span class="detail-value">{{ failedTests }}</span>
              <span class="detail-label">Failed</span>
            </span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-header">
            <Shield class="stat-icon" />
            <h3 class="stat-title">Policies</h3>
          </div>
          <div class="stat-value">{{ totalPolicies }}</div>
          <div class="stat-label">Configured</div>
          <div class="stat-detail">
            <span class="stat-detail-item">
              <span class="detail-value">{{ activePolicies }}</span>
              <span class="detail-label">Active</span>
            </span>
            <span class="stat-detail-item">
              <span class="detail-value">{{ rbacPolicies }}</span>
              <span class="detail-label">RBAC</span>
            </span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-header">
            <Users class="stat-icon" />
            <h3 class="stat-title">Teams</h3>
          </div>
          <div class="stat-value">{{ totalTeams }}</div>
          <div class="stat-label">Monitored</div>
          <div class="stat-detail">
            <span class="stat-detail-item">
              <span class="detail-value">{{ avgCompliance }}</span>
              <span class="detail-label">Avg Compliance</span>
            </span>
          </div>
        </div>
      </div>

      <!-- System Health -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">
            <Activity class="title-icon" />
            System Health
          </h2>
        </div>
        <div class="health-grid">
          <div class="health-item">
            <div class="health-label">API Status</div>
            <div class="health-value status-healthy">Healthy</div>
            <div class="health-detail">Response time: 45ms</div>
          </div>
          <div class="health-item">
            <div class="health-label">Database</div>
            <div class="health-value status-healthy">Connected</div>
            <div class="health-detail">Last sync: 2 min ago</div>
          </div>
          <div class="health-item">
            <div class="health-label">Test Runner</div>
            <div class="health-value status-healthy">Running</div>
            <div class="health-detail">Queue: 3 pending</div>
          </div>
          <div class="health-item">
            <div class="health-label">Storage</div>
            <div class="health-value status-warning">75% Used</div>
            <div class="health-detail">2.1 GB / 2.8 GB</div>
          </div>
        </div>
      </div>

      <!-- Recent Activity -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">
            <Clock class="title-icon" />
            Recent Activity
          </h2>
        </div>
        <div class="activity-list">
          <div
            v-for="(activity, index) in recentActivity"
            :key="index"
            class="activity-item"
          >
            <div class="activity-icon" :class="`activity-${activity.type}`">
              <component :is="activity.icon" class="icon" />
            </div>
            <div class="activity-content">
              <div class="activity-title">{{ activity.title }}</div>
              <div class="activity-meta">
                {{ activity.user }} • {{ formatTimeAgo(activity.timestamp) }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">Quick Actions</h2>
        </div>
        <div class="actions-grid">
          <button @click="activeTab = 'applications'; showCreateModal = true" class="quick-action-btn">
            <Plus class="action-icon" />
            <span>Register Application</span>
          </button>
          <button @click="runSystemTest" class="quick-action-btn">
            <TestTube class="action-icon" />
            <span>Run System Test</span>
          </button>
          <button @click="viewSystemLogs" class="quick-action-btn">
            <Activity class="action-icon" />
            <span>View System Logs</span>
          </button>
          <button @click="exportConfiguration" class="quick-action-btn">
            <Settings class="action-icon" />
            <span>Export Configuration</span>
          </button>
        </div>
      </div>

      <!-- Integration Management -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">Integrations & CI/CD</h2>
          <p class="section-description">Manage external integrations and CI/CD pipeline configurations</p>
        </div>
        <div class="integration-cards-grid">
          <router-link to="/admin/ci-cd" class="integration-card">
            <div class="integration-card-header">
              <GitBranch class="integration-icon" />
              <h3 class="integration-title">CI/CD Integration</h3>
            </div>
            <p class="integration-description">
              Configure and monitor compliance testing in GitHub Actions and Jenkins pipelines
            </p>
            <div class="integration-footer">
              <span class="integration-link">Configure →</span>
            </div>
          </router-link>

          <router-link to="/admin/integrations" class="integration-card">
            <div class="integration-card-header">
              <Plug class="integration-icon" />
              <h3 class="integration-title">External Integrations</h3>
            </div>
            <p class="integration-description">
              Connect and manage SAST, DAST, DBT, and Great Expectations integrations
            </p>
            <div class="integration-footer">
              <span class="integration-link">Manage →</span>
            </div>
          </router-link>
        </div>
      </div>

      <!-- History & Audit -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">History & Audit</h2>
          <p class="section-description">View test execution history, audit logs, and activity feed</p>
        </div>
        <div class="integration-cards-grid">
          <router-link to="/admin/history" class="integration-card">
            <div class="integration-card-header">
              <Clock class="integration-icon" />
              <h3 class="integration-title">History</h3>
            </div>
            <p class="integration-description">
              View test execution history, audit logs, and system activity feed with comprehensive filtering
            </p>
            <div class="integration-footer">
              <span class="integration-link">View History →</span>
            </div>
          </router-link>
        </div>
      </div>

      <!-- Environments -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">Environments</h2>
          <p class="section-description">Manage ephemeral environments for testing and validation</p>
        </div>
        <div class="integration-cards-grid">
          <router-link to="/admin/environments" class="integration-card">
            <div class="integration-card-header">
              <Cloud class="integration-icon" />
              <h3 class="integration-title">Ephemeral Environments</h3>
            </div>
            <p class="integration-description">
              Create, monitor, and manage ephemeral environments for PR testing and validation
            </p>
            <div class="integration-footer">
              <span class="integration-link">Manage →</span>
            </div>
          </router-link>
        </div>
      </div>

      <!-- Remediation & Workflows -->
      <div class="section-card">
        <div class="section-header-inline">
          <h2 class="section-title">Remediation & Workflows</h2>
          <p class="section-description">Configure ticketing integrations, SLA policies, and automated remediation</p>
        </div>
        <div class="integration-cards-grid">
          <router-link to="/admin/ticketing" class="integration-card">
            <div class="integration-card-header">
              <Ticket class="integration-icon" />
              <h3 class="integration-title">Ticketing Integrations</h3>
            </div>
            <p class="integration-description">
              Connect Jira, ServiceNow, or GitHub to automatically create tickets for violations
            </p>
            <div class="integration-footer">
              <span class="integration-link">Configure →</span>
            </div>
          </router-link>

          <router-link to="/admin/sla" class="integration-card">
            <div class="integration-card-header">
              <Clock class="integration-icon" />
              <h3 class="integration-title">SLA Management</h3>
            </div>
            <p class="integration-description">
              Define service level agreements and escalation workflows for violation remediation
            </p>
            <div class="integration-footer">
              <span class="integration-link">Manage →</span>
            </div>
          </router-link>
        </div>
      </div>
    </div>

    <!-- Banner Management Tab -->
    <div v-if="activeTab === 'banners'" class="tab-content">
      <div class="section-header">
        <div>
          <h2 class="section-title">
            <Megaphone class="title-icon" />
            Site Banners
          </h2>
          <p class="section-description">
            Manage site-wide notification banners displayed to all users
          </p>
        </div>
        <button @click="showBannerModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Banner
        </button>
      </div>

      <!-- Banners List -->
      <div class="banners-list">
        <div
          v-for="banner in banners"
          :key="banner.id"
          class="banner-card"
          :class="`banner-${banner.type}`"
        >
          <div class="banner-card-header">
            <div class="banner-card-title-row">
              <div class="banner-type-badge" :class="`badge-${banner.type}`">
                <component :is="getBannerIcon(banner.type)" class="badge-icon" />
                {{ banner.type.toUpperCase() }}
              </div>
              <div class="banner-status-toggle">
                <label class="toggle-label">
                  <input
                    type="checkbox"
                    :checked="banner.isActive"
                    @change="toggleBanner(banner.id)"
                    class="toggle-input"
                  />
                  <span class="toggle-slider"></span>
                  <span class="toggle-text">{{ banner.isActive ? 'Active' : 'Inactive' }}</span>
                </label>
              </div>
            </div>
          </div>
          <div class="banner-card-content">
            <div class="banner-preview" :class="`preview-${banner.type}`">
              <div class="preview-content">
                <component :is="getBannerIcon(banner.type)" class="preview-icon" />
                <div class="preview-text">
                  <p class="preview-message" v-html="banner.message"></p>
                  <a
                    v-if="banner.linkUrl && banner.linkText"
                    :href="banner.linkUrl"
                    class="preview-link"
                  >
                    {{ banner.linkText }}
                  </a>
                </div>
              </div>
            </div>
            <div class="banner-card-details">
              <div class="detail-item">
                <span class="detail-label">Priority</span>
                <span class="detail-value">{{ banner.priority || 0 }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Dismissible</span>
                <span class="detail-value">{{ banner.dismissible ? 'Yes' : 'No' }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Created</span>
                <span class="detail-value">{{ formatDate(banner.createdAt) }}</span>
              </div>
            </div>
          </div>
          <div class="banner-card-actions">
            <button @click="editBanner(banner)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="deleteBanner(banner.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="banners.length === 0" class="empty-state">
        <Megaphone class="empty-icon" />
        <h3>No banners configured</h3>
        <p>Create a banner to display important messages to all users</p>
        <button @click="showBannerModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Banner
        </button>
      </div>
    </div>

    <!-- Application Management Tab -->
    <div v-if="activeTab === 'applications'" class="tab-content">
      <div class="section-header">
        <div>
          <h2 class="section-title">
            <Layers class="title-icon" />
            Registered Applications
          </h2>
          <p class="section-description">
            Register and manage applications that Sentinel will test against
          </p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Register Application
        </button>
      </div>

      <!-- Loading/Error States -->
      <div v-if="loadingApplications" class="loading-state">
        <div class="loading">Loading applications...</div>
      </div>
      <div v-if="applicationsError" class="error-state">
        <div class="error">{{ applicationsError }}</div>
        <button @click="loadApplications" class="btn-retry">
          Retry
        </button>
      </div>

      <!-- Applications List -->
      <div v-if="!loadingApplications && !applicationsError" class="applications-grid">
        <div
          v-for="app in applications"
          :key="app.id"
          class="application-card"
        >
          <div class="app-header">
            <div class="app-title-row">
              <h3 class="app-name">{{ app.name }}</h3>
              <span class="app-status" :class="`status-${app.status}`">
                {{ app.status }}
              </span>
            </div>
            <p class="app-id">ID: {{ app.id }}</p>
          </div>

          <div class="app-details">
            <div class="detail-item">
              <span class="detail-label">Type</span>
              <span class="detail-value">{{ app.type }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Base URL</span>
              <span class="detail-value">{{ app.baseUrl || 'N/A' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Team</span>
              <span class="detail-value">{{ app.team || 'Unassigned' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Registered</span>
              <span class="detail-value">{{ formatDate(app.registeredAt) }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Last Test</span>
              <span class="detail-value">{{ app.lastTestAt ? formatDate(app.lastTestAt) : 'Never' }}</span>
            </div>
          </div>

          <div class="app-actions">
            <button @click="editApplication(app)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="testApplication(app)" class="action-btn test-btn">
              <TestTube class="action-icon" />
              Test
            </button>
            <button @click="deleteApplication(app.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="applications.length === 0" class="empty-state">
        <Layers class="empty-icon" />
        <h3>No applications registered</h3>
        <p>Register your first application to start running compliance tests</p>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Register Application
        </button>
      </div>
    </div>

    <!-- Validators Tab -->
    <div v-if="activeTab === 'validators'" class="tab-content">
      <div class="section-header">
        <div>
          <h2 class="section-title">
            <Shield class="title-icon" />
            Validators
          </h2>
          <p class="section-description">
            Manage registered validators that execute compliance tests
          </p>
        </div>
        <button @click="showAddValidatorModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Validator
        </button>
      </div>

      <!-- Loading/Error States -->
      <div v-if="loadingValidators" class="loading-state">
        <div class="loading">Loading validators...</div>
      </div>
      <div v-if="validatorsError" class="error-state">
        <div class="error">{{ validatorsError }}</div>
        <button @click="loadValidators" class="btn-retry">
          Retry
        </button>
      </div>

      <!-- Validators List -->
      <div v-if="!loadingValidators && !validatorsError" class="validators-grid">
        <ValidatorCard
          v-for="validator in validators"
          :key="validator.id"
          :validator="validator"
          @view="viewValidator"
          @toggle="toggleValidator"
          @test="testValidator"
          @delete="deleteValidator"
        />
      </div>

      <div v-if="!loadingValidators && !validatorsError && validators.length === 0" class="empty-state">
        <Shield class="empty-icon" />
        <h3>No validators registered</h3>
        <p>Add your first validator to start running compliance tests</p>
        <button @click="showAddValidatorModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Validator
        </button>
      </div>
    </div>

    <!-- Create/Edit Banner Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showBannerModal" class="modal-overlay" @click="closeBannerModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Megaphone class="modal-title-icon" />
                <h2>{{ editingBanner ? 'Edit Banner' : 'Create Banner' }}</h2>
              </div>
              <button @click="closeBannerModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveBanner" class="banner-form">
                <div class="form-row">
                  <div class="form-group">
                    <label>Banner Type *</label>
                    <Dropdown
                      v-model="bannerForm.type"
                      :options="bannerTypeOptions"
                      placeholder="Select type..."
                    />
                  </div>
                  <div class="form-group">
                    <label>Priority</label>
                    <input
                      v-model.number="bannerForm.priority"
                      type="number"
                      min="0"
                      max="100"
                      placeholder="0"
                    />
                    <small>Higher priority banners appear first</small>
                  </div>
                </div>
                <div class="form-group">
                  <label>Message *</label>
                  <textarea
                    v-model="bannerForm.message"
                    rows="3"
                    required
                    placeholder="Enter banner message (HTML supported)..."
                  ></textarea>
                  <small>You can use HTML tags for formatting</small>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Link URL (Optional)</label>
                    <input
                      v-model="bannerForm.linkUrl"
                      type="url"
                      placeholder="https://example.com"
                    />
                  </div>
                  <div class="form-group">
                    <label>Link Text (Optional)</label>
                    <input
                      v-model="bannerForm.linkText"
                      type="text"
                      placeholder="Learn more"
                    />
                  </div>
                </div>
                <div class="form-group">
                  <label class="checkbox-label">
                    <input
                      v-model="bannerForm.dismissible"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Allow users to dismiss this banner</span>
                  </label>
                </div>
                <div class="form-group">
                  <label class="checkbox-label">
                    <input
                      v-model="bannerForm.isActive"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Activate banner immediately</span>
                  </label>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeBannerModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="!isBannerFormValid">
                    {{ editingBanner ? 'Update' : 'Create' }} Banner
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Create/Edit Application Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal" class="modal-overlay" @click="closeModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Layers class="modal-title-icon" />
                <h2>{{ editingApp ? 'Edit Application' : 'Register Application' }}</h2>
              </div>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveApplication" class="app-form">
                <div class="form-group">
                  <label>Application Name *</label>
                  <input
                    v-model="appForm.name"
                    type="text"
                    required
                    placeholder="e.g., Research Tracker API"
                  />
                </div>
                <div class="form-group">
                  <label>Application ID *</label>
                  <input
                    v-model="appForm.id"
                    type="text"
                    required
                    placeholder="e.g., research-tracker-api"
                    :disabled="editingApp"
                  />
                  <small>Unique identifier (cannot be changed after creation)</small>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Application Type *</label>
                    <Dropdown
                      v-model="appForm.type"
                      :options="appTypeOptions"
                      placeholder="Select type..."
                    />
                  </div>
                  <div class="form-group">
                    <label>Status</label>
                    <Dropdown
                      v-model="appForm.status"
                      :options="statusOptions"
                      placeholder="Select status..."
                    />
                  </div>
                </div>
                <div class="form-group">
                  <label>Base URL</label>
                  <input
                    v-model="appForm.baseUrl"
                    type="url"
                    placeholder="https://api.example.com"
                  />
                  <small>Base URL for API endpoints (optional)</small>
                </div>
                <div class="form-group">
                  <label>Team</label>
                  <input
                    v-model="appForm.team"
                    type="text"
                    placeholder="e.g., Platform Team"
                  />
                </div>
                <div class="form-group">
                  <label>Description</label>
                  <textarea
                    v-model="appForm.description"
                    rows="3"
                    placeholder="Brief description of the application..."
                  ></textarea>
                </div>
                <div class="form-group">
                  <label>Configuration (JSON)</label>
                  <textarea
                    v-model="appForm.configJson"
                    rows="6"
                    placeholder='{"database": "postgresql", "auth": "jwt"}'
                    class="json-input"
                  ></textarea>
                  <small>Additional configuration as JSON (optional)</small>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="!isFormValid">
                    {{ editingApp ? 'Update' : 'Register' }} Application
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Validator Detail Modal -->
    <ValidatorDetailModal
      :show="showValidatorDetailModal"
      :validator="selectedValidator"
      @close="showValidatorDetailModal = false; selectedValidator = null"
      @edit="editValidator"
      @toggle="toggleValidator"
      @test="testValidator"
    />

    <!-- Add/Edit Validator Modal -->
    <AddValidatorModal
      :show="showAddValidatorModal"
      :validator="editingValidator"
      @close="showAddValidatorModal = false; editingValidator = null"
      @submit="handleValidatorSubmit"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Teleport } from 'vue';
import axios from 'axios';
import {
  Settings,
  Layers,
  Plus,
  Edit,
  Trash2,
  TestTube,
  X,
  BarChart3,
  Activity,
  Server,
  Users,
  Shield,
  Clock,
  AlertCircle,
  Info,
  AlertTriangle,
  CheckCircle2,
  Megaphone,
  GitBranch,
  Plug,
  Cloud,
  Ticket
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';
import ValidatorCard from '../components/ValidatorCard.vue';
import ValidatorDetailModal from '../components/ValidatorDetailModal.vue';
import AddValidatorModal from '../components/AddValidatorModal.vue';

const activeTab = ref<'overview' | 'applications' | 'banners' | 'validators'>('overview');
const showCreateModal = ref(false);
const editingApp = ref<any>(null);
const showBannerModal = ref(false);
const editingBanner = ref<any>(null);

// Validators data
const validators = ref<any[]>([]);
const loadingValidators = ref(false);
const validatorsError = ref<string | null>(null);
const showAddValidatorModal = ref(false);
const showValidatorDetailModal = ref(false);
const selectedValidator = ref<any>(null);
const editingValidator = ref<any>(null);

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin' }
];

const tabs = [
  { id: 'overview', label: 'Overview', icon: BarChart3 },
  { id: 'applications', label: 'Applications', icon: Layers },
  { id: 'banners', label: 'Banners', icon: Megaphone },
  { id: 'validators', label: 'Validators', icon: Shield }
];

// Applications data
const applications = ref<any[]>([]);
const loadingApplications = ref(false);
const applicationsError = ref<string | null>(null);

const loadApplications = async () => {
  try {
    loadingApplications.value = true;
    applicationsError.value = null;
    const response = await axios.get('/api/applications');
    applications.value = response.data.map((app: any) => ({
      ...app,
      registeredAt: new Date(app.registeredAt),
      lastTestAt: app.lastTestAt ? new Date(app.lastTestAt) : null,
      updatedAt: new Date(app.updatedAt)
    }));
  } catch (err: any) {
    applicationsError.value = err.message || 'Failed to load applications';
    console.error('Error loading applications:', err);
  } finally {
    loadingApplications.value = false;
  }
};

const appForm = ref({
  name: '',
  id: '',
  type: 'api',
  status: 'active',
  baseUrl: '',
  team: '',
  description: '',
  configJson: '{}'
});

// Banners
const banners = ref([
  {
    id: '1',
    message: 'System maintenance scheduled for this weekend. Some services may be unavailable.',
    type: 'warning' as const,
    isActive: true,
    dismissible: true,
    linkUrl: 'https://status.example.com',
    linkText: 'View status page',
    priority: 10,
    createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000)
  },
  {
    id: '2',
    message: 'New compliance policies have been updated. <strong>Review changes</strong> to ensure your applications remain compliant.',
    type: 'info' as const,
    isActive: true,
    dismissible: true,
    linkUrl: '/policies',
    linkText: 'View policies',
    priority: 5,
    createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000)
  },
  {
    id: '3',
    message: 'All systems operational. No issues detected.',
    type: 'success' as const,
    isActive: false,
    dismissible: false,
    priority: 1,
    createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000)
  }
]);

const bannerForm = ref({
  message: '',
  type: 'info' as 'info' | 'warning' | 'error' | 'success',
  dismissible: true,
  isActive: false,
  linkUrl: '',
  linkText: '',
  priority: 0
});

const bannerTypeOptions = computed(() => [
  { label: 'Info', value: 'info' },
  { label: 'Warning', value: 'warning' },
  { label: 'Error', value: 'error' },
  { label: 'Success', value: 'success' }
]);

const isBannerFormValid = computed(() => {
  return bannerForm.value.message.trim().length > 0;
});

const getBannerIcon = (type: string) => {
  switch (type) {
    case 'info':
      return Info;
    case 'warning':
      return AlertTriangle;
    case 'error':
      return AlertCircle;
    case 'success':
      return CheckCircle2;
    default:
      return Info;
  }
};

const toggleBanner = (id: string) => {
  const banner = banners.value.find(b => b.id === id);
  if (banner) {
    banner.isActive = !banner.isActive;
  }
};

const editBanner = (banner: any) => {
  editingBanner.value = banner;
  bannerForm.value = {
    message: banner.message,
    type: banner.type,
    dismissible: banner.dismissible,
    isActive: banner.isActive,
    linkUrl: banner.linkUrl || '',
    linkText: banner.linkText || '',
    priority: banner.priority || 0
  };
  showBannerModal.value = true;
};

const deleteBanner = async (id: string) => {
  if (!confirm('Are you sure you want to delete this banner?')) {
    return;
  }
  
  const index = banners.value.findIndex(b => b.id === id);
  if (index !== -1) {
    banners.value.splice(index, 1);
  }
};

const saveBanner = () => {
  if (editingBanner.value) {
    // Update existing
    const index = banners.value.findIndex(b => b.id === editingBanner.value.id);
    if (index !== -1) {
      banners.value[index] = {
        ...banners.value[index],
        message: bannerForm.value.message,
        type: bannerForm.value.type,
        dismissible: bannerForm.value.dismissible,
        isActive: bannerForm.value.isActive,
        linkUrl: bannerForm.value.linkUrl || undefined,
        linkText: bannerForm.value.linkText || undefined,
        priority: bannerForm.value.priority
      };
    }
  } else {
    // Create new
    banners.value.push({
      id: String(Date.now()),
      message: bannerForm.value.message,
      type: bannerForm.value.type,
      dismissible: bannerForm.value.dismissible,
      isActive: bannerForm.value.isActive,
      linkUrl: bannerForm.value.linkUrl || undefined,
      linkText: bannerForm.value.linkText || undefined,
      priority: bannerForm.value.priority,
      createdAt: new Date()
    });
  }

  closeBannerModal();
};

const closeBannerModal = () => {
  showBannerModal.value = false;
  editingBanner.value = null;
  bannerForm.value = {
    message: '',
    type: 'info',
    dismissible: true,
    isActive: false,
    linkUrl: '',
    linkText: '',
    priority: 0
  };
};

const loadValidators = async () => {
  try {
    loadingValidators.value = true;
    validatorsError.value = null;
    const response = await axios.get('/api/validators');
    validators.value = response.data.map((v: any) => ({
      ...v,
      registeredAt: new Date(v.registeredAt),
      lastRunAt: v.lastRunAt ? new Date(v.lastRunAt) : null,
      updatedAt: new Date(v.updatedAt),
    }));
  } catch (err: any) {
    validatorsError.value = err.message || 'Failed to load validators';
    console.error('Error loading validators:', err);
  } finally {
    loadingValidators.value = false;
  }
};

const viewValidator = (validator: any) => {
  selectedValidator.value = validator;
  showValidatorDetailModal.value = true;
};

const toggleValidator = async (validator: any) => {
  try {
    if (validator.enabled) {
      await axios.patch(`/api/validators/${validator.id}/disable`);
    } else {
      await axios.patch(`/api/validators/${validator.id}/enable`);
    }
    await loadValidators();
  } catch (err: any) {
    console.error('Error toggling validator:', err);
    alert(err.response?.data?.message || 'Failed to toggle validator');
  }
};

const testValidator = async (validator: any) => {
  try {
    const response = await axios.post(`/api/validators/${validator.id}/test`);
    alert(response.data.message || 'Connection test successful');
  } catch (err: any) {
    console.error('Error testing validator:', err);
    alert(err.response?.data?.message || 'Connection test failed');
  }
};

const deleteValidator = async (validator: any) => {
  if (!confirm(`Are you sure you want to delete validator "${validator.name}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/validators/${validator.id}`);
    await loadValidators();
  } catch (err: any) {
    console.error('Error deleting validator:', err);
    alert(err.response?.data?.message || 'Failed to delete validator');
  }
};

const handleValidatorSubmit = async (data: any) => {
  try {
    if (editingValidator.value) {
      await axios.patch(`/api/validators/${editingValidator.value.id}`, {
        name: data.name,
        description: data.description,
        config: data.config,
        enabled: data.enabled,
      });
    } else {
      await axios.post('/api/validators', data);
    }
    await loadValidators();
    showAddValidatorModal.value = false;
    editingValidator.value = null;
  } catch (err: any) {
    console.error('Error saving validator:', err);
    alert(err.response?.data?.message || 'Failed to save validator');
  }
};

const editValidator = (validator: any) => {
  editingValidator.value = validator;
  showAddValidatorModal.value = true;
};

onMounted(() => {
  loadApplications();
  loadValidators();
});

const appTypeOptions = computed(() => [
  { label: 'API', value: 'api' },
  { label: 'Web Application', value: 'web' },
  { label: 'Microservice', value: 'microservice' },
  { label: 'Data Pipeline', value: 'pipeline' },
  { label: 'Database', value: 'database' }
]);

const statusOptions = computed(() => [
  { label: 'Active', value: 'active' },
  { label: 'Inactive', value: 'inactive' },
  { label: 'Maintenance', value: 'maintenance' }
]);

const isFormValid = computed(() => {
  return appForm.value.name && appForm.value.id && appForm.value.type;
});

// Overview statistics
const activeApplications = computed(() => {
  return applications.value.filter(app => app.status === 'active').length;
});

const inactiveApplications = computed(() => {
  return applications.value.filter(app => app.status === 'inactive').length;
});

const totalTests = computed(() => 1247);
const passedTests = computed(() => 1189);
const failedTests = computed(() => 58);
const totalPolicies = computed(() => 12);
const activePolicies = computed(() => 10);
const rbacPolicies = computed(() => 7);
const totalTeams = computed(() => 5);
const avgCompliance = computed(() => '87.5%');

const recentActivity = ref([
  {
    type: 'test',
    icon: TestTube,
    title: 'Test suite executed for Research Tracker API',
    user: 'system',
    timestamp: new Date(Date.now() - 5 * 60 * 1000)
  },
  {
    type: 'register',
    icon: Layers,
    title: 'New application registered: User Service',
    user: 'admin@example.com',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000)
  },
  {
    type: 'policy',
    icon: Shield,
    title: 'Policy updated: Default Access Control Policy',
    user: 'admin@example.com',
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000)
  },
  {
    type: 'violation',
    icon: Activity,
    title: 'Violation detected: Unauthorized access attempt',
    user: 'system',
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000)
  }
]);

const formatTimeAgo = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
};

const runSystemTest = () => {
  console.log('Run system test');
  // In real app: trigger system test
};

const viewSystemLogs = () => {
  console.log('View system logs');
  // In real app: navigate to logs page
};

const exportConfiguration = () => {
  console.log('Export configuration');
  // In real app: download configuration JSON
};

const formatDate = (date: Date): string => {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};

const editApplication = (app: any) => {
  editingApp.value = app;
  appForm.value = {
    name: app.name,
    id: app.id,
    type: app.type,
    status: app.status,
    baseUrl: app.baseUrl || '',
    team: app.team || '',
    description: app.description || '',
    configJson: JSON.stringify(app.config || {}, null, 2)
  };
  showCreateModal.value = true;
};

const testApplication = async (app: any) => {
  try {
    await axios.post(`/api/applications/${app.id}/test`);
    // Reload applications to update lastTestAt
    await loadApplications();
    // In real app: router.push(`/tests?app=${app.id}`);
  } catch (err: any) {
    console.error('Error updating test time:', err);
    alert('Failed to update test time');
  }
};

const deleteApplication = async (id: string) => {
  if (!confirm(`Are you sure you want to delete application "${id}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/applications/${id}`);
    await loadApplications();
  } catch (err: any) {
    console.error('Error deleting application:', err);
    alert(err.response?.data?.message || 'Failed to delete application');
  }
};

const saveApplication = async () => {
  try {
    const config = appForm.value.configJson 
      ? JSON.parse(appForm.value.configJson)
      : {};

    const payload = {
      name: appForm.value.name,
      type: appForm.value.type,
      status: appForm.value.status,
      baseUrl: appForm.value.baseUrl || undefined,
      team: appForm.value.team || undefined,
      description: appForm.value.description || undefined,
      config: Object.keys(config).length > 0 ? config : undefined
    };

    if (editingApp.value) {
      // Update existing
      await axios.patch(`/api/applications/${editingApp.value.id}`, payload);
    } else {
      // Create new
      await axios.post('/api/applications', {
        ...payload,
        id: appForm.value.id
      });
    }

    await loadApplications();
    closeModal();
  } catch (err: any) {
    if (err.response?.data?.message) {
      alert(err.response.data.message);
    } else if (err.message?.includes('JSON')) {
      alert('Invalid JSON in configuration field');
    } else {
      alert('Failed to save application');
    }
    console.error('Error saving application:', err);
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingApp.value = null;
  appForm.value = {
    name: '',
    id: '',
    type: 'api',
    status: 'active',
    baseUrl: '',
    team: '',
    description: '',
    configJson: '{}'
  };
};
</script>

<style scoped>
.admin-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
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

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 32px;
  gap: 24px;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
  display: flex;
  align-items: center;
  gap: 12px;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.section-description {
  font-size: 0.9rem;
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
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.applications-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

.application-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.2s;
}

.application-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.app-header {
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.app-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.app-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.app-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-inactive {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.status-maintenance {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.app-id {
  font-size: 0.875rem;
  color: #718096;
  font-family: 'Courier New', monospace;
  margin: 0;
}

.app-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 20px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.875rem;
}

.detail-label {
  color: #718096;
  font-weight: 500;
}

.detail-value {
  color: #ffffff;
  font-weight: 500;
}

.app-actions {
  display: flex;
  gap: 8px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.edit-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.test-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
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
  margin-bottom: 24px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 700px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
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
  padding: 24px;
}

.app-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.json-input {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* Overview Styles */
.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
}

.stat-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.2s;
}

.stat-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.stat-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.stat-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.stat-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 0;
}

.stat-value {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 4px;
  line-height: 1;
}

.stat-label {
  font-size: 0.875rem;
  color: #718096;
  margin-bottom: 16px;
}

.stat-detail {
  display: flex;
  gap: 24px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.stat-detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-detail-item .detail-value {
  font-size: 1.125rem;
  font-weight: 600;
  color: #4facfe;
}

.stat-detail-item .detail-label {
  font-size: 0.75rem;
  color: #718096;
}

.section-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
}

.section-header-inline {
  margin-bottom: 20px;
}

.health-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.health-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.health-label {
  font-size: 0.875rem;
  color: #718096;
  margin-bottom: 8px;
  font-weight: 500;
}

.health-value {
  font-size: 1.25rem;
  font-weight: 600;
  margin-bottom: 4px;
}

.status-healthy {
  color: #22c55e;
}

.status-warning {
  color: #fbbf24;
}

.status-error {
  color: #fc8181;
}

.health-detail {
  font-size: 0.75rem;
  color: #a0aec0;
}

.activity-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.activity-item {
  display: flex;
  align-items: flex-start;
  gap: 16px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(79, 172, 254, 0.1);
  transition: all 0.2s;
}

.activity-item:hover {
  background: rgba(15, 20, 25, 0.6);
  border-color: rgba(79, 172, 254, 0.2);
}

.activity-icon {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.activity-icon .icon {
  width: 20px;
  height: 20px;
}

.activity-test {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.activity-register {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.activity-policy {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.activity-violation {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.activity-content {
  flex: 1;
}

.activity-title {
  font-size: 0.9rem;
  font-weight: 500;
  color: #ffffff;
  margin-bottom: 4px;
}

.activity-meta {
  font-size: 0.75rem;
  color: #718096;
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.quick-action-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.quick-action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.quick-action-btn .action-icon {
  width: 32px;
  height: 32px;
}

.quick-action-btn span {
  font-size: 0.875rem;
}

/* Banner Management Styles */
.banners-list {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.banner-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.2s;
}

.banner-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.banner-card-header {
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.banner-card-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
}

.banner-type-badge {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.badge-icon {
  width: 14px;
  height: 14px;
}

.badge-info {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.badge-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.badge-error {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.badge-success {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-size: 0.875rem;
  color: #a0aec0;
}

.toggle-input {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: relative;
  width: 44px;
  height: 24px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  transition: all 0.2s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 18px;
  height: 18px;
  left: 3px;
  top: 3px;
  background: #718096;
  border-radius: 50%;
  transition: all 0.2s;
}

.toggle-input:checked + .toggle-slider {
  background: rgba(79, 172, 254, 0.4);
}

.toggle-input:checked + .toggle-slider::before {
  transform: translateX(20px);
  background: #4facfe;
}

.toggle-text {
  font-weight: 500;
}

.banner-card-content {
  margin-bottom: 16px;
}

.banner-preview {
  padding: 16px;
  border-radius: 12px;
  margin-bottom: 16px;
  border: 1px solid;
}

.preview-info {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.preview-warning {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.3);
  color: #fbbf24;
}

.preview-error {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.preview-success {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.preview-content {
  display: flex;
  align-items: center;
  gap: 12px;
}

.preview-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.preview-text {
  flex: 1;
}

.preview-message {
  margin: 0;
  font-size: 0.9rem;
  font-weight: 500;
  line-height: 1.5;
}

.preview-link {
  display: inline-block;
  margin-top: 8px;
  color: inherit;
  text-decoration: underline;
  font-weight: 600;
  font-size: 0.875rem;
}

.banner-card-details {
  display: flex;
  gap: 24px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.banner-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  font-size: 0.9rem;
  color: #ffffff;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
  accent-color: #4facfe;
}

.loading-state,
.error-state {
  padding: 40px;
  text-align: center;
}

.loading {
  color: #4facfe;
  font-size: 1.1rem;
}

.error {
  color: #fc8181;
  font-size: 1.1rem;
  margin-bottom: 16px;
}

.integration-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
  margin-top: 24px;
}

.integration-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  text-decoration: none;
  color: inherit;
  transition: all 0.3s;
  display: flex;
  flex-direction: column;
  cursor: pointer;
}

.integration-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.integration-card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.integration-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
  flex-shrink: 0;
}

.integration-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.integration-description {
  font-size: 0.9rem;
  color: #a0aec0;
  line-height: 1.6;
  margin-bottom: 16px;
  flex: 1;
}

.integration-footer {
  display: flex;
  justify-content: flex-end;
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.integration-link {
  color: #4facfe;
  font-weight: 600;
  font-size: 0.9rem;
  transition: color 0.2s;
}

.integration-card:hover .integration-link {
  color: #00f2fe;
}

.btn-retry {
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-retry:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

/* Validators Styles */
.validators-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}
</style>

