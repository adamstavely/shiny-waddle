<template>
  <div class="targets-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Targets
              <span class="hero-subtitle">Application & Platform Management</span>
            </h1>
            <p class="hero-description">
              Manage your testing targets including applications and platform instances. 
              Track compliance scores, assign test batteries, and monitor security posture 
              across all your targets.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/applications')" class="btn-primary">View Applications</button>
              <button @click="navigateTo('/applications/platform-instances')" class="btn-secondary">View Platform Instances</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 400 300" class="targets-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="targetGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="targetGradientLight" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.6 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.4 }" />
                  </linearGradient>
                  <radialGradient id="targetGlow">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.3 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0 }" />
                  </radialGradient>
                </defs>
                
                <!-- Background glow effect -->
                <circle cx="200" cy="150" r="140" fill="url(#targetGlow)" />
                
                <!-- Central Target Icon -->
                <g transform="translate(200, 120)">
                  <!-- Outer rings -->
                  <circle cx="0" cy="0" r="45" fill="none" stroke="url(#targetGradient)" stroke-width="2" opacity="0.4" />
                  <circle cx="0" cy="0" r="35" fill="none" stroke="url(#targetGradient)" stroke-width="2" opacity="0.5" />
                  <circle cx="0" cy="0" r="25" fill="none" stroke="url(#targetGradient)" stroke-width="2.5" opacity="0.7" />
                  <!-- Center dot -->
                  <circle cx="0" cy="0" r="8" fill="url(#targetGradient)" />
                  <!-- Crosshair lines -->
                  <line x1="-45" y1="0" x2="-15" y2="0" stroke="url(#targetGradient)" stroke-width="2" opacity="0.6" />
                  <line x1="15" y1="0" x2="45" y2="0" stroke="url(#targetGradient)" stroke-width="2" opacity="0.6" />
                  <line x1="0" y1="-45" x2="0" y2="-15" stroke="url(#targetGradient)" stroke-width="2" opacity="0.6" />
                  <line x1="0" y1="15" x2="0" y2="45" stroke="url(#targetGradient)" stroke-width="2" opacity="0.6" />
                </g>
                
                <!-- Application Card (left) -->
                <g transform="translate(60, 200)">
                  <rect x="-40" y="-25" width="80" height="50" rx="6" fill="url(#targetGradientLight)" stroke="url(#targetGradient)" stroke-width="2" opacity="0.8" />
                  <rect x="-35" y="-20" width="70" height="40" rx="4" fill="url(#targetGradient)" opacity="0.2" />
                  <!-- App icon -->
                  <rect x="-15" y="-8" width="30" height="16" rx="2" fill="url(#targetGradient)" opacity="0.6" />
                  <circle cx="0" cy="0" r="3" fill="url(#targetGradient)" />
                  <!-- Connection line to center -->
                  <line x1="40" y1="0" x2="140" y2="-50" stroke="url(#targetGradient)" stroke-width="2" opacity="0.4" stroke-dasharray="4,4" />
                </g>
                
                <!-- Platform Instance Card (right) -->
                <g transform="translate(340, 200)">
                  <rect x="-40" y="-25" width="80" height="50" rx="6" fill="url(#targetGradientLight)" stroke="url(#targetGradient)" stroke-width="2" opacity="0.8" />
                  <rect x="-35" y="-20" width="70" height="40" rx="4" fill="url(#targetGradient)" opacity="0.2" />
                  <!-- Platform icon -->
                  <rect x="-20" y="-10" width="40" height="20" rx="2" fill="none" stroke="url(#targetGradient)" stroke-width="2" opacity="0.6" />
                  <rect x="-15" y="-5" width="30" height="10" rx="1" fill="url(#targetGradient)" opacity="0.3" />
                  <!-- Connection line to center -->
                  <line x1="-40" y1="0" x2="-140" y2="-50" stroke="url(#targetGradient)" stroke-width="2" opacity="0.4" stroke-dasharray="4,4" />
                </g>
                
                <!-- Floating particles/indicators -->
                <circle cx="120" cy="80" r="3" fill="url(#targetGradient)" opacity="0.6">
                  <animate attributeName="opacity" values="0.6;1;0.6" dur="2s" repeatCount="indefinite" />
                </circle>
                <circle cx="280" cy="80" r="3" fill="url(#targetGradient)" opacity="0.6">
                  <animate attributeName="opacity" values="0.6;1;0.6" dur="2s" begin="0.5s" repeatCount="indefinite" />
                </circle>
                <circle cx="150" cy="250" r="2.5" fill="url(#targetGradient)" opacity="0.5">
                  <animate attributeName="opacity" values="0.5;0.9;0.5" dur="1.5s" begin="1s" repeatCount="indefinite" />
                </circle>
                <circle cx="250" cy="250" r="2.5" fill="url(#targetGradient)" opacity="0.5">
                  <animate attributeName="opacity" values="0.5;0.9;0.5" dur="1.5s" begin="0.3s" repeatCount="indefinite" />
                </circle>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-section">
      <h2 class="section-title">Quick Stats</h2>
      <div class="stats-grid">
        <div class="stat-card" @click="navigateTo('/applications')">
          <Database class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.applications }}</div>
            <div class="stat-label">Applications</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/applications/platform-instances')">
          <Settings class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.platformInstances }}</div>
            <div class="stat-label">Platform Instances</div>
          </div>
        </div>
        <div class="stat-card">
          <CheckCircle2 class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.complianceScore }}%</div>
            <div class="stat-label">Avg Compliance Score</div>
          </div>
        </div>
        <div class="stat-card">
          <AlertCircle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.activeFindings }}</div>
            <div class="stat-label">Active Findings</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="actions-section">
      <h2 class="section-title">Quick Actions</h2>
      <div class="actions-grid">
        <button @click="navigateTo('/applications')" class="action-card">
          <Database class="action-icon" />
          <span>View Applications</span>
        </button>
        <button @click="navigateTo('/applications/platform-instances')" class="action-card">
          <Settings class="action-icon" />
          <span>View Platform Instances</span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Database,
  Settings,
  CheckCircle2,
  AlertCircle
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Targets', to: '/targets' }
];

const stats = ref({
  applications: 0,
  platformInstances: 0,
  complianceScore: 0,
  activeFindings: 0
});

const loadStats = async () => {
  try {
    const [appsRes, platformInstancesRes] = await Promise.all([
      axios.get('/api/v1/applications').catch(() => ({ data: [] })),
      axios.get('/api/v1/platform-instances').catch(() => ({ data: [] }))
    ]);
    
    const applications = appsRes.data || [];
    const platformInstances = platformInstancesRes.data || [];
    
    // Calculate average compliance score
    let totalScore = 0;
    let scoreCount = 0;
    
    for (const app of applications) {
      try {
        const scoreRes = await axios.get(`/api/v1/applications/${app.id}/compliance-score`).catch(() => ({ data: { score: 0 } }));
        if (scoreRes.data?.score !== undefined) {
          totalScore += scoreRes.data.score;
          scoreCount++;
        }
      } catch (err) {
        // Ignore errors for individual apps
      }
    }
    
    const avgComplianceScore = scoreCount > 0 ? Math.round(totalScore / scoreCount) : 0;
    
    // Count active findings (simplified - could be enhanced)
    let activeFindings = 0;
    for (const app of applications) {
      try {
        const issuesRes = await axios.get(`/api/v1/applications/${app.id}/issues`).catch(() => ({ data: [] }));
        if (issuesRes.data) {
          activeFindings += issuesRes.data.filter((issue: any) => issue.status === 'open' || issue.status === 'active').length;
        }
      } catch (err) {
        // Ignore errors for individual apps
      }
    }
    
    stats.value = {
      applications: applications.length,
      platformInstances: platformInstances.length,
      complianceScore: avgComplianceScore,
      activeFindings
    };
  } catch (err) {
    console.error('Error loading stats:', err);
  }
};

const navigateTo = (path: string) => {
  router.push(path);
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.targets-overview-page {
  padding: var(--spacing-xl);
  max-width: 1400px;
  margin: 0 auto;
}

/* Hero Section - matching TestsOverview style */
.hero-section {
  margin-bottom: 4rem;
}

.hero-card {
  position: relative;
  background: var(--gradient-card);
  opacity: 0.8;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-2xl);
  overflow: hidden;
  box-shadow: var(--shadow-lg);
}

.hero-background {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-image: 
    radial-gradient(circle at 20% 50%, var(--border-color-muted) 0%, transparent 50%),
    radial-gradient(circle at 80% 80%, var(--border-color-muted) 0%, transparent 50%);
  opacity: 0.6;
  pointer-events: none;
}

.hero-content {
  position: relative;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-2xl);
  align-items: center;
  z-index: 1;
}

.hero-text {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.hero-title {
  font-size: var(--font-size-5xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0;
  line-height: 1.2;
}

.hero-subtitle {
  display: block;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-normal);
  color: var(--color-primary);
  margin-top: var(--spacing-sm);
}

.hero-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin: 0;
}

.hero-actions {
  display: flex;
  gap: var(--spacing-md);
  margin-top: var(--spacing-xs);
}

.btn-primary,
.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  text-decoration: none;
  display: inline-block;
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
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  color: var(--color-primary);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
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
  height: auto;
}

.targets-svg {
  width: 100%;
  height: auto;
}

/* Quick Stats Section */
.stats-section {
  margin-bottom: 4rem;
}

.section-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
  opacity: 0.8;
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.stat-icon {
  width: 48px;
  height: 48px;
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
}

.action-card:hover {
  background: var(--color-bg-overlay-dark);
  opacity: 0.8;
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
}
</style>
