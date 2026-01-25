<template>
  <div class="platform-config-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Platform Config
              <span class="hero-subtitle">Configuration Validation</span>
            </h1>
            <p class="hero-description">
              Validate and verify platform configurations to ensure they meet security and 
              compliance requirements. Use the configuration validator to check infrastructure 
              settings, deployment configurations, and system parameters before they go live.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/configuration-validation')" class="btn-primary">Validate Configuration</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 250 200" class="platform-config-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="configGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                </defs>
                
                <!-- Settings Gear -->
                <g transform="translate(125, 100)">
                  <circle cx="0" cy="0" r="40" fill="url(#configGradient)" opacity="0.2" stroke="url(#configGradient)" stroke-width="2"/>
                  <circle cx="0" cy="0" r="30" fill="url(#configGradient)" opacity="0.3" stroke="url(#configGradient)" stroke-width="1.5"/>
                  
                  <!-- Gear teeth -->
                  <rect x="-2" y="-45" width="4" height="12" fill="url(#configGradient)" opacity="0.8"/>
                  <rect x="-2" y="33" width="4" height="12" fill="url(#configGradient)" opacity="0.8"/>
                  <rect x="-45" y="-2" width="12" height="4" fill="url(#configGradient)" opacity="0.8"/>
                  <rect x="33" y="-2" width="12" height="4" fill="url(#configGradient)" opacity="0.8"/>
                  
                  <rect x="28" y="-28" width="4" height="10" fill="url(#configGradient)" opacity="0.8" transform="rotate(45)"/>
                  <rect x="-32" y="28" width="4" height="10" fill="url(#configGradient)" opacity="0.8" transform="rotate(45)"/>
                  <rect x="28" y="28" width="4" height="10" fill="url(#configGradient)" opacity="0.8" transform="rotate(-45)"/>
                  <rect x="-32" y="-28" width="4" height="10" fill="url(#configGradient)" opacity="0.8" transform="rotate(-45)"/>
                  
                  <!-- Center circle -->
                  <circle cx="0" cy="0" r="8" fill="#00f2fe" opacity="0.9"/>
                </g>
                
                <!-- Config Files -->
                <rect x="30" y="30" width="40" height="50" rx="4" fill="url(#configGradient)" opacity="0.3" stroke="url(#configGradient)" stroke-width="2"/>
                <line x1="40" y1="45" x2="60" y2="45" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                <line x1="40" y1="55" x2="55" y2="55" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                
                <rect x="180" y="30" width="40" height="50" rx="4" fill="url(#configGradient)" opacity="0.3" stroke="url(#configGradient)" stroke-width="2"/>
                <line x1="190" y1="45" x2="210" y2="45" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                <line x1="190" y1="55" x2="205" y2="55" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                
                <!-- Checkmark -->
                <path d="M 50 65 L 58 73 L 72 55" stroke="#00f2fe" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/>
                <path d="M 200 65 L 208 73 L 222 55" stroke="#00f2fe" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/>
                
                <!-- Connection lines -->
                <line x1="70" y1="55" x2="85" y2="80" stroke="url(#configGradient)" stroke-width="2" opacity="0.5"/>
                <line x1="180" y1="55" x2="165" y2="80" stroke="url(#configGradient)" stroke-width="2" opacity="0.5"/>
                
                <!-- Accent dots -->
                <circle cx="125" cy="30" r="3" fill="#00f2fe" opacity="0.8"/>
                <circle cx="50" cy="80" r="2.5" fill="#4facfe" opacity="0.7"/>
                <circle cx="200" cy="80" r="2.5" fill="#4facfe" opacity="0.7"/>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- How It Works Section -->
    <div class="how-it-works-section">
      <h2 class="section-title">How It Works</h2>
      <p class="section-description">
        Validate platform configurations to ensure security and compliance
      </p>
      
      <div class="explanation-grid">
        <div class="explanation-card">
          <div class="explanation-icon">
            <Shield />
          </div>
          <h3 class="explanation-title">Config Validator</h3>
          <p class="explanation-text">
            Validate infrastructure configurations, deployment settings, and system parameters. 
            Check for security misconfigurations, compliance violations, and best practice 
            deviations before deploying to production.
          </p>
          <button @click="navigateTo('/configuration-validation')" class="explanation-link">Run Validator →</button>
        </div>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-section">
      <h2 class="section-title">Quick Stats</h2>
      <div class="stats-grid">
        <div class="stat-card">
          <Shield class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.validations || 0 }}</div>
            <div class="stat-label">Validations Run</div>
          </div>
        </div>
        <div class="stat-card">
          <CheckCircle2 class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.passed || 0 }}</div>
            <div class="stat-label">Passed</div>
          </div>
        </div>
        <div class="stat-card">
          <XCircle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.failed || 0 }}</div>
            <div class="stat-label">Failed</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Shield, CheckCircle2, XCircle } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Platform Config', to: '/platform-config' },
];

const stats = ref({
  validations: 0,
  passed: 0,
  failed: 0,
});

const navigateTo = (path: string) => {
  router.push(path);
};

const loadStats = async () => {
  try {
    // TODO: Load validation stats from API when backend is ready
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.platform-config-overview-page {
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
  border-radius: var(--border-radius-2xl);
  padding: var(--spacing-xl) var(--spacing-2xl);
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 50%, #1a1f2e 100%);
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
  letter-spacing: -1px;
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

.btn-primary {
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.3);
}

.hero-visual {
  display: flex;
  justify-content: center;
  align-items: center;
}

.svg-container {
  width: 100%;
  max-width: 400px;
}

.platform-config-svg {
  width: 100%;
  height: auto;
}

.how-it-works-section {
  margin-bottom: 3rem;
}

.section-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.section-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xl);
}

.explanation-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--spacing-lg);
}

.explanation-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.explanation-card:hover {
  background: var(--color-bg-overlay-dark);
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.explanation-icon {
  width: 48px;
  height: 48px;
  color: var(--color-primary);
  margin-bottom: var(--spacing-base);
}

.explanation-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.explanation-text {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin-bottom: var(--spacing-base);
}

.explanation-link {
  color: var(--color-primary);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  transition: var(--transition-all);
}

.explanation-link:hover {
  color: var(--color-secondary);
}

.stats-section {
  margin-bottom: var(--spacing-xl);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-base);
}

.stat-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  display: flex;
  align-items: center;
  gap: var(--spacing-base);
  transition: var(--transition-all);
}

.stat-card:hover {
  background: var(--color-bg-overlay-dark);
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
  margin-bottom: var(--spacing-xs);
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
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

