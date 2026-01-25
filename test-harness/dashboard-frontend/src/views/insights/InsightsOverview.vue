<template>
  <div class="insights-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Insights & Reports
              <span class="hero-subtitle">Analytics & Reporting</span>
            </h1>
            <p class="hero-description">
              Comprehensive analytics, dashboards, and reporting for your compliance testing. 
              View test runs, generate reports, analyze trends, and get predictive insights into 
              your security posture.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/insights/analytics')" class="btn-primary">View Analytics</button>
              <button @click="navigateTo('/insights/runs')" class="btn-secondary">View Runs</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 250 200" class="insights-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="insightsGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                </defs>
                
                <!-- Chart bars -->
                <rect x="40" y="120" width="30" height="60" rx="2" fill="url(#insightsGradient)" opacity="0.6"/>
                <rect x="85" y="100" width="30" height="80" rx="2" fill="url(#insightsGradient)" opacity="0.6"/>
                <rect x="130" y="80" width="30" height="100" rx="2" fill="url(#insightsGradient)" opacity="0.6"/>
                <rect x="175" y="90" width="30" height="90" rx="2" fill="url(#insightsGradient)" opacity="0.6"/>
                
                <!-- Trend line -->
                <path d="M 55 150 Q 100 130 145 110 T 190 100" 
                      stroke="url(#insightsGradient)" 
                      stroke-width="3" 
                      fill="none" 
                      opacity="0.8"/>
                
                <!-- Data points -->
                <circle cx="55" cy="150" r="4" fill="#00f2fe" opacity="0.9"/>
                <circle cx="100" cy="130" r="4" fill="#00f2fe" opacity="0.9"/>
                <circle cx="145" cy="110" r="4" fill="#00f2fe" opacity="0.9"/>
                <circle cx="190" cy="100" r="4" fill="#00f2fe" opacity="0.9"/>
                
                <!-- Report/document icon -->
                <rect x="50" y="30" width="50" height="60" rx="2" fill="url(#insightsGradient)" opacity="0.3" stroke="url(#insightsGradient)" stroke-width="2"/>
                <line x1="60" y1="50" x2="85" y2="50" stroke="url(#insightsGradient)" stroke-width="2" opacity="0.6"/>
                <line x1="60" y1="65" x2="85" y2="65" stroke="url(#insightsGradient)" stroke-width="2" opacity="0.6"/>
                <line x1="60" y1="80" x2="75" y2="80" stroke="url(#insightsGradient)" stroke-width="2" opacity="0.6"/>
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
        <div class="stat-card" @click="navigateTo('/insights/runs')">
          <PlayCircle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.totalRuns || 0 }}</div>
            <div class="stat-label">Total Runs</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/insights/reports')">
          <FileText class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.totalReports || 0 }}</div>
            <div class="stat-label">Saved Reports</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/insights/trends')">
          <TrendingUp class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.avgCompliance || 0 }}%</div>
            <div class="stat-label">Avg Compliance</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/insights/analytics')">
          <BarChart3 class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.activeTests || 0 }}</div>
            <div class="stat-label">Active Tests</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Insights Types Section -->
    <div class="insights-types-section">
      <h2 class="section-title">Insights & Reports</h2>
      <p class="section-description">
        Navigate to different analytics and reporting areas
      </p>
      
      <div class="insights-types-grid">
        <div class="insight-type-card" @click="navigateTo('/insights/analytics')">
          <BarChart3 class="insight-type-icon" />
          <h3 class="insight-type-title">Analytics</h3>
          <p class="insight-type-description">Comprehensive analytics and dashboards</p>
        </div>
        
        <div class="insight-type-card" @click="navigateTo('/insights/predictions')">
          <TrendingUp class="insight-type-icon" />
          <h3 class="insight-type-title">Predictions</h3>
          <p class="insight-type-description">Predictive insights and forecasting</p>
        </div>
        
        <div class="insight-type-card" @click="navigateTo('/insights/runs')">
          <PlayCircle class="insight-type-icon" />
          <h3 class="insight-type-title">Runs</h3>
          <p class="insight-type-description">View test battery executions and results</p>
          <div class="insight-type-badge">{{ stats.totalRuns || 0 }} runs</div>
        </div>
        
        <div class="insight-type-card" @click="navigateTo('/insights/reports')">
          <FileText class="insight-type-icon" />
          <h3 class="insight-type-title">Reports</h3>
          <p class="insight-type-description">Compliance snapshots and saved reports</p>
          <div class="insight-type-badge">{{ stats.totalReports || 0 }} reports</div>
        </div>
        
        <div class="insight-type-card" @click="navigateTo('/insights/trends')">
          <TrendingUp class="insight-type-icon" />
          <h3 class="insight-type-title">Trends</h3>
          <p class="insight-type-description">Compliance trends and historical analysis</p>
        </div>
      </div>
    </div>
    
    <!-- Quick Actions Section -->
    <div class="actions-section">
      <h2 class="section-title">Quick Actions</h2>
      <div class="actions-grid">
        <button @click="navigateTo('/insights/reports')" class="action-card">
          <Plus class="action-icon" />
          Create Compliance Snapshot
        </button>
        <button @click="navigateTo('/insights/runs')" class="action-card">
          <PlayCircle class="action-icon" />
          View Recent Runs
        </button>
        <button @click="navigateTo('/insights/trends')" class="action-card">
          <TrendingUp class="action-icon" />
          View Trends
        </button>
        <button @click="navigateTo('/insights/analytics')" class="action-card">
          <BarChart3 class="action-icon" />
          View Analytics Dashboard
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  PlayCircle,
  FileText,
  TrendingUp,
  BarChart3,
  Plus
} from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights & Reports' }
];

const stats = ref({
  totalRuns: 0,
  totalReports: 0,
  avgCompliance: 0,
  activeTests: 0
});

const navigateTo = (path: string) => {
  router.push(path);
};

const loadStats = async () => {
  try {
    // Load runs count
    try {
      const runsResponse = await axios.get('/api/v1/runs');
      stats.value.totalRuns = runsResponse.data?.length || 0;
    } catch (err) {
      console.log('Runs API not available');
    }
    
    // Load reports count
    try {
      const reportsResponse = await axios.get('/api/v1/reports');
      stats.value.totalReports = reportsResponse.data?.length || 0;
    } catch (err) {
      console.log('Reports API not available');
    }
    
    // Calculate average compliance (placeholder)
    stats.value.avgCompliance = 85;
    stats.value.activeTests = 0;
  } catch (err) {
    console.error('Error loading stats:', err);
  }
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.insights-overview-page {
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
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
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
  font-size: var(--font-size-4xl);
  font-weight: 700;
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
  line-height: 1.1;
  letter-spacing: -1px;
}

.hero-subtitle {
  display: block;
  font-size: var(--font-size-2xl);
  margin-top: var(--spacing-sm);
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  font-weight: 600;
}

.hero-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin-bottom: 32px;
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
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: var(--color-text-primary);
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

.insights-svg {
  width: 100%;
  height: auto;
}

/* Stats Section */
.stats-section {
  margin-bottom: 3rem;
}

.section-title {
  font-size: var(--font-size-2xl);
  font-weight: 700;
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
  gap: 1.5rem;
}

.stat-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  cursor: pointer;
  transition: all 0.2s;
}

.stat-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
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
  margin-bottom: var(--spacing-xs);
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

/* Insights Types Section */
.insights-types-section {
  margin-bottom: 3rem;
}

.insights-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1.5rem;
}

.insight-type-card {
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

.insight-type-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.insight-type-icon {
  width: 40px;
  height: 40px;
  color: #4facfe;
  margin-bottom: 0.5rem;
}

.insight-type-title {
  font-size: var(--font-size-xl);
  font-weight: 600;
  color: var(--color-text-primary);
  margin: 0;
}

.insight-type-description {
  font-size: var(--font-size-sm);
  color: #a0aec0;
  margin: 0;
  line-height: 1.5;
}

.insight-type-badge {
  margin-top: auto;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: 600;
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
  color: #4facfe;
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
  .insights-types-grid {
    grid-template-columns: 1fr;
  }
}
</style>
