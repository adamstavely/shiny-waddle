<template>
  <div class="policies-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Policies & Configuration
              <span class="hero-subtitle">Comprehensive Policy Management</span>
            </h1>
            <p class="hero-description">
              Manage access control policies, data classification, platform configurations, and compliance 
              standards. Define RBAC and ABAC policies, manage exceptions, and ensure 
              your systems meet security and compliance requirements.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/policies/access-control')" class="btn-primary">View Access Control</button>
              <button @click="navigateTo('/policies/data-classification')" class="btn-secondary">Data Classification</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 250 200" class="policy-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="policyGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="policyGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.8 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.6 }" />
                  </linearGradient>
                </defs>
                
                <!-- Shield representing policies -->
                <path d="M 125 20 L 180 50 L 180 100 Q 180 140 125 170 Q 70 140 70 100 L 70 50 Z" 
                      fill="url(#policyGradient)" opacity="0.3" stroke="url(#policyGradient)" stroke-width="2"/>
                <path d="M 125 40 L 160 60 L 160 95 Q 160 125 125 145 Q 90 125 90 95 L 90 60 Z" 
                      fill="url(#policyGradient)" opacity="0.4" stroke="url(#policyGradient)" stroke-width="1.5"/>
                
                <!-- Policy layers -->
                <rect x="30" y="60" width="60" height="40" rx="4" fill="url(#policyGradient)" opacity="0.2" stroke="url(#policyGradient)" stroke-width="1.5"/>
                <rect x="160" y="60" width="60" height="40" rx="4" fill="url(#policyGradient)" opacity="0.2" stroke="url(#policyGradient)" stroke-width="1.5"/>
                <rect x="95" y="120" width="60" height="40" rx="4" fill="url(#policyGradient)" opacity="0.2" stroke="url(#policyGradient)" stroke-width="1.5"/>
                
                <!-- Checkmark in center -->
                <path d="M 110 95 L 125 110 L 145 85" :style="{ stroke: 'var(--color-secondary)', strokeWidth: '4', fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round', opacity: 0.9 }"/>
                
                <!-- Accent dots -->
                <circle cx="60" cy="80" r="3" :style="{ fill: 'var(--color-primary)', opacity: 0.7 }"/>
                <circle cx="190" cy="80" r="3" :style="{ fill: 'var(--color-primary)', opacity: 0.7 }"/>
                <circle cx="125" cy="140" r="3" :style="{ fill: 'var(--color-secondary)', opacity: 0.6 }"/>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Stats Section -->
    <div class="stats-section">
      <h2 class="section-title">Quick Stats</h2>
      <div class="stats-grid">
        <div class="stat-card" @click="navigateTo('/policies/access-control')">
          <Shield class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.accessControlPolicies || 0 }}</div>
            <div class="stat-label">Access Control Policies</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/policies/data-classification')">
          <FileText class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.classificationLevels || 0 }}</div>
            <div class="stat-label">Classification Levels</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/policies/exceptions')">
          <AlertTriangle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.exceptions || 0 }}</div>
            <div class="stat-label">Active Exceptions</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Policy Types Section -->
    <div class="policy-types-section">
      <h2 class="section-title">Policy Categories</h2>
      <p class="section-description">
        Navigate to different policy management areas organized by category
      </p>
      
      <!-- Access Control Policies Group -->
      <div class="policy-group">
        <div class="policy-group-header">
          <Shield class="group-header-icon" />
          <h3 class="policy-group-title">Access Control Policies</h3>
          <p class="policy-group-description">Manage RBAC, ABAC, and exception policies</p>
        </div>
        <div class="policy-types-grid">
          <div class="policy-type-card" @click="navigateTo('/policies/access-control')">
            <Shield class="policy-type-icon" />
            <h4 class="policy-type-title">Access Control</h4>
            <p class="policy-type-description">Manage RBAC and ABAC access control policies</p>
            <div class="policy-type-badge">{{ stats.accessControlPolicies || 0 }} policies</div>
          </div>
          <div class="policy-type-card" @click="navigateTo('/policies/exceptions')">
            <AlertTriangle class="policy-type-icon" />
            <h4 class="policy-type-title">Exceptions</h4>
            <p class="policy-type-description">Manage policy exceptions</p>
            <div class="policy-type-badge">{{ stats.exceptions || 0 }} exceptions</div>
          </div>
        </div>
      </div>

      <!-- Data Policies Group -->
      <div class="policy-group">
        <div class="policy-group-header">
          <Database class="group-header-icon" />
          <h3 class="policy-group-title">Data Policies</h3>
          <p class="policy-group-description">Configure data classification, contracts, and compliance mappings</p>
        </div>
        <div class="policy-types-grid">
          <div class="policy-type-card" @click="navigateTo('/policies/data-classification')">
            <FileText class="policy-type-icon" />
            <h4 class="policy-type-title">Data Classification</h4>
            <p class="policy-type-description">Define data classification levels and rules</p>
            <div class="policy-type-badge">{{ stats.classificationLevels || 0 }} levels</div>
          </div>
          <div class="policy-type-card" @click="navigateTo('/policies/data-contracts')">
            <Database class="policy-type-icon" />
            <h4 class="policy-type-title">Data Contracts</h4>
            <p class="policy-type-description">Configure data contract policies</p>
            <div class="policy-type-badge">{{ stats.dataContracts || 0 }} contracts</div>
          </div>
          <div class="policy-type-card" @click="navigateTo('/policies/standards-mapping')">
            <CheckCircle2 class="policy-type-icon" />
            <h4 class="policy-type-title">Standards Mapping</h4>
            <p class="policy-type-description">Map policies to compliance standards</p>
            <div class="policy-type-badge">{{ stats.standards || 0 }} standards</div>
          </div>
        </div>
      </div>

    </div>
    
    <!-- Quick Actions Section -->
    <div class="actions-section">
      <h2 class="section-title">Quick Actions</h2>
      <div class="actions-grid">
        <button @click="navigateTo('/policies/access-control')" class="action-card">
          <Plus class="action-icon" />
          Create Access Control Policy
        </button>
        <button @click="navigateTo('/policies/data-classification')" class="action-card">
          <Plus class="action-icon" />
          Create Classification Level
        </button>
        <button @click="navigateTo('/policies/exceptions')" class="action-card">
          <Plus class="action-icon" />
          Request Exception
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Shield,
  FileText,
  Settings,
  AlertTriangle,
  CheckCircle2,
  Database,
  Workflow,
  Plus
} from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies' }
];

const stats = ref({
  accessControlPolicies: 0,
  classificationLevels: 0,
  exceptions: 0,
  standards: 0,
  dataContracts: 0,
});

const navigateTo = (path: string) => {
  router.push(path);
};

const loadStats = async () => {
  try {
    // Load access control policies
    const policiesResponse = await axios.get('/api/policies');
    stats.value.accessControlPolicies = policiesResponse.data?.length || 0;
    
    // Load classification levels
    try {
      const levelsResponse = await axios.get('/api/v1/data-classification/levels');
      stats.value.classificationLevels = levelsResponse.data?.length || 0;
    } catch (err) {
      // API might not exist yet
      console.log('Classification levels API not available');
    }
    
    // Load other stats as APIs become available
    // For now, set defaults
    stats.value.exceptions = 0;
    stats.value.standards = 0;
    stats.value.dataContracts = 0;
  } catch (err) {
    console.error('Error loading stats:', err);
  }
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.policies-overview-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.hero-section {
  margin-bottom: 3rem;
}

.hero-card {
  position: relative;
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card-full);
  border: var(--border-width-thin) solid var(--border-color-primary);
  box-shadow: var(--shadow-xl);
  overflow: hidden;
}

.hero-background {
  position: absolute;
  inset: 0;
  opacity: 0.1;
  background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
}

.hero-content {
  position: relative;
  z-index: 10;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-2xl);
  align-items: center;
}

.hero-text {
  flex: 1;
}

.hero-title {
  font-size: var(--font-size-5xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
  line-height: 1.1;
  letter-spacing: var(--letter-spacing-tight);
}

.hero-subtitle {
  display: block;
  font-size: var(--font-size-3xl);
  margin-top: var(--spacing-sm);
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  font-weight: var(--font-weight-semibold);
}

.hero-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin-bottom: var(--spacing-xl);
}

.hero-actions {
  display: flex;
  gap: var(--spacing-md);
}

.btn-primary,
.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.btn-secondary {
  background: var(--border-color-muted);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
}

.btn-secondary:hover {
  background: var(--border-color-primary);
  border-color: var(--border-color-primary-active);
}

.hero-visual {
  display: flex;
  align-items: center;
  justify-content: center;
}

.svg-container {
  width: 100%;
  max-width: 400px;
}

.policy-svg {
  width: 100%;
  height: auto;
}

/* Stats Section */
.stats-section {
  margin-bottom: 3rem;
}

.section-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.section-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: var(--spacing-lg);
}

.stat-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  cursor: pointer;
  transition: var(--transition-all);
}

.stat-card:hover {
  background: var(--color-bg-overlay-dark);
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.stat-icon {
  width: var(--spacing-2xl);
  height: var(--spacing-2xl);
  color: var(--color-primary);
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

/* Policy Types Section */
.policy-types-section {
  margin-bottom: var(--spacing-2xl);
}

.policy-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: var(--spacing-lg);
}

.policy-type-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.policy-type-card:hover {
  background: var(--color-bg-overlay-dark);
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.policy-type-icon {
  width: var(--spacing-xl);
  height: var(--spacing-xl);
  color: var(--color-primary);
  margin-bottom: var(--spacing-sm);
}

.policy-group {
  margin-bottom: var(--spacing-2xl);
}

.policy-group-header {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.group-header-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
  margin-top: 2px;
}

.policy-group-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.policy-group-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.policy-type-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.policy-type-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
  line-height: 1.5;
}

.policy-type-badge {
  margin-top: auto;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  display: inline-block;
  width: fit-content;
}

/* Quick Actions Section */
.actions-section {
  margin-bottom: var(--spacing-2xl);
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.action-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-sm);
  cursor: pointer;
  transition: var(--transition-all);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  text-align: center;
}

.action-card:hover {
  background: var(--color-bg-overlay-dark);
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: var(--color-primary);
}

@media (max-width: 768px) {
  .hero-content {
    grid-template-columns: 1fr;
    gap: 2rem;
  }
  
  .hero-title {
    font-size: var(--font-size-2xl);
  }
  
  .hero-visual {
    order: -1;
  }
  
  .stats-grid,
  .policy-types-grid {
    grid-template-columns: 1fr;
  }
}
</style>
