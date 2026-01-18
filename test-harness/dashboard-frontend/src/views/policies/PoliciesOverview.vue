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
              standards. Define RBAC and ABAC policies, configure baselines, manage exceptions, and ensure 
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
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:1" />
                  </linearGradient>
                  <linearGradient id="policyGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.8" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:0.6" />
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
                <path d="M 110 95 L 125 110 L 145 85" stroke="#00f2fe" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/>
                
                <!-- Accent dots -->
                <circle cx="60" cy="80" r="3" fill="#4facfe" opacity="0.7"/>
                <circle cx="190" cy="80" r="3" fill="#4facfe" opacity="0.7"/>
                <circle cx="125" cy="140" r="3" fill="#00f2fe" opacity="0.6"/>
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
        <div class="stat-card" @click="navigateTo('/policies/platform-config')">
          <Settings class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.platformBaselines || 0 }}</div>
            <div class="stat-label">Platform Baselines</div>
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
      <h2 class="section-title">Policy Types</h2>
      <p class="section-description">
        Navigate to different policy management areas
      </p>
      
      <div class="policy-types-grid">
        <div class="policy-type-card" @click="navigateTo('/policies/access-control')">
          <Shield class="policy-type-icon" />
          <h3 class="policy-type-title">Access Control</h3>
          <p class="policy-type-description">Manage RBAC and ABAC access control policies</p>
          <div class="policy-type-badge">{{ stats.accessControlPolicies || 0 }} policies</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/data-classification')">
          <FileText class="policy-type-icon" />
          <h3 class="policy-type-title">Data Classification</h3>
          <p class="policy-type-description">Define data classification levels and rules</p>
          <div class="policy-type-badge">{{ stats.classificationLevels || 0 }} levels</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/platform-config')">
          <Settings class="policy-type-icon" />
          <h3 class="policy-type-title">Platform Config</h3>
          <p class="policy-type-description">Manage platform configuration baselines</p>
          <div class="policy-type-badge">{{ stats.platformBaselines || 0 }} baselines</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/exceptions')">
          <AlertTriangle class="policy-type-icon" />
          <h3 class="policy-type-title">Exceptions</h3>
          <p class="policy-type-description">Manage policy exceptions and allowlists</p>
          <div class="policy-type-badge">{{ stats.exceptions || 0 }} exceptions</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/standards-mapping')">
          <CheckCircle2 class="policy-type-icon" />
          <h3 class="policy-type-title">Standards Mapping</h3>
          <p class="policy-type-description">Map policies to compliance standards</p>
          <div class="policy-type-badge">{{ stats.standards || 0 }} standards</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/data-contracts')">
          <Database class="policy-type-icon" />
          <h3 class="policy-type-title">Data Contracts</h3>
          <p class="policy-type-description">Configure data contract policies</p>
          <div class="policy-type-badge">{{ stats.dataContracts || 0 }} contracts</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/salesforce')">
          <Cloud class="policy-type-icon" />
          <h3 class="policy-type-title">Salesforce Baselines</h3>
          <p class="policy-type-description">Manage Salesforce configuration baselines</p>
          <div class="policy-type-badge">{{ stats.salesforceBaselines || 0 }} baselines</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/elastic')">
          <Server class="policy-type-icon" />
          <h3 class="policy-type-title">Elastic Baselines</h3>
          <p class="policy-type-description">Manage Elastic configuration baselines</p>
          <div class="policy-type-badge">{{ stats.elasticBaselines || 0 }} baselines</div>
        </div>
        
        <div class="policy-type-card" @click="navigateTo('/policies/idp-platform')">
          <Container class="policy-type-icon" />
          <h3 class="policy-type-title">IDP / Kubernetes</h3>
          <p class="policy-type-description">Manage IDP and Kubernetes baselines</p>
          <div class="policy-type-badge">{{ stats.idpBaselines || 0 }} baselines</div>
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
        <button @click="navigateTo('/policies/platform-config')" class="action-card">
          <Plus class="action-icon" />
          Create Platform Baseline
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
  Cloud,
  Server,
  Container,
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
  platformBaselines: 0,
  exceptions: 0,
  standards: 0,
  dataContracts: 0,
  salesforceBaselines: 0,
  elasticBaselines: 0,
  idpBaselines: 0
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
    stats.value.platformBaselines = 0;
    stats.value.exceptions = 0;
    stats.value.standards = 0;
    stats.value.dataContracts = 0;
    stats.value.salesforceBaselines = 0;
    stats.value.elasticBaselines = 0;
    stats.value.idpBaselines = 0;
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
  padding: 24px;
}

.hero-section {
  margin-bottom: 3rem;
}

.hero-card {
  position: relative;
  border-radius: 24px;
  padding: 48px 64px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 50%, #1a1f2e 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
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
  gap: 64px;
  align-items: center;
}

.hero-text {
  flex: 1;
}

.hero-title {
  font-size: 4rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 16px;
  line-height: 1.1;
  letter-spacing: -1px;
}

.hero-subtitle {
  display: block;
  font-size: 2rem;
  margin-top: 12px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  font-weight: 600;
}

.hero-description {
  font-size: 1.125rem;
  color: #a0aec0;
  line-height: 1.6;
  margin-bottom: 32px;
}

.hero-actions {
  display: flex;
  gap: 16px;
}

.btn-primary,
.btn-secondary {
  padding: 12px 24px;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.3);
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
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
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 1.5rem;
}

.section-description {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 1.5rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.5rem;
}

.stat-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  cursor: pointer;
  transition: all 0.2s;
}

.stat-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.stat-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

/* Policy Types Section */
.policy-types-section {
  margin-bottom: 3rem;
}

.policy-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1.5rem;
}

.policy-type-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.policy-type-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.policy-type-icon {
  width: 40px;
  height: 40px;
  color: #4facfe;
  margin-bottom: 0.5rem;
}

.policy-type-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.policy-type-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
  line-height: 1.5;
}

.policy-type-badge {
  margin-top: auto;
  padding: 4px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
  display: inline-block;
  width: fit-content;
}

/* Quick Actions Section */
.actions-section {
  margin-bottom: 3rem;
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.action-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  cursor: pointer;
  transition: all 0.2s;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
  text-align: center;
}

.action-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
}

@media (max-width: 768px) {
  .hero-content {
    grid-template-columns: 1fr;
    gap: 2rem;
  }
  
  .hero-title {
    font-size: 2rem;
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
