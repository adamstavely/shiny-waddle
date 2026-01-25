<template>
  <div class="access-control-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Access Control
              <span class="hero-subtitle">Policy & Identity Management</span>
            </h1>
            <p class="hero-description">
              Manage and configure access control policies, resources, and identity providers. 
              Define RBAC and ABAC policies, configure resources with attributes, simulate user 
              access scenarios, and validate policy decisions to ensure proper access control 
              across your applications.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/policies')" class="btn-primary">View Policies</button>
              <button @click="navigateTo('/resources')" class="btn-secondary">Manage Resources</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 300 240" class="access-control-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="accessGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="lockGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.4 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.4 }" />
                  </linearGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                </defs>
                
                <!-- Central Lock Icon -->
                <g transform="translate(150, 120)">
                  <!-- Lock body -->
                  <rect x="-25" y="20" width="50" height="50" rx="6" 
                        fill="url(#lockGradient)" 
                        stroke="url(#accessGradient)" 
                        stroke-width="3"
                        opacity="0.5"/>
                  
                  <!-- Lock shackle -->
                  <path d="M -15 20 Q -15 0, 0 0 Q 15 0, 15 20" 
                        fill="none" 
                        stroke="url(#accessGradient)" 
                        stroke-width="3.5"
                        stroke-linecap="round"
                        opacity="0.7"/>
                  
                  <!-- Keyhole -->
                  <circle cx="0" cy="35" r="8" 
                          fill="var(--color-bg-primary)" 
                          stroke="url(#accessGradient)" 
                          stroke-width="2"/>
                  <rect x="-2" y="35" width="4" height="12" rx="1" 
                        fill="var(--color-bg-primary)" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2"/>
                  
                  <!-- Keyhole glow -->
                  <circle cx="0" cy="35" r="8" 
                          fill="url(#accessGradient)" 
                          opacity="0.2"
                          filter="url(#glow)"/>
                </g>
                
                <!-- Shield around lock -->
                <g transform="translate(150, 120)">
                  <path d="M 0 -60 L 50 -30 L 50 30 L 0 80 L -50 30 L -50 -30 Z" 
                        fill="url(#lockGradient)" 
                        opacity="0.2" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2.5"
                        stroke-dasharray="5,5"/>
                  
                  <!-- Inner shield -->
                  <path d="M 0 -50 L 40 -25 L 40 25 L 0 70 L -40 25 L -40 -25 Z" 
                        fill="url(#lockGradient)" 
                        opacity="0.15" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2"/>
                </g>
                
                <!-- Policy documents around the lock -->
                <g transform="translate(150, 120)">
                  <!-- Top policy document -->
                  <rect x="-20" y="-80" width="40" height="50" rx="3" 
                        fill="url(#lockGradient)" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2"
                        opacity="0.4"/>
                  <line x1="-15" y1="-65" x2="15" y2="-65" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="-15" y1="-55" x2="10" y2="-55" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="-15" y1="-45" x2="15" y2="-45" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  
                  <!-- Left policy document -->
                  <rect x="-100" y="-10" width="40" height="50" rx="3" 
                        fill="url(#lockGradient)" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2"
                        opacity="0.4"/>
                  <line x1="-95" y1="5" x2="-65" y2="5" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="-95" y1="15" x2="-70" y2="15" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="-95" y1="25" x2="-65" y2="25" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  
                  <!-- Right policy document -->
                  <rect x="60" y="-10" width="40" height="50" rx="3" 
                        fill="url(#lockGradient)" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2"
                        opacity="0.4"/>
                  <line x1="65" y1="5" x2="95" y2="5" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="65" y1="15" x2="90" y2="15" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="65" y1="25" x2="95" y2="25" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  
                  <!-- Bottom policy document -->
                  <rect x="-20" y="60" width="40" height="50" rx="3" 
                        fill="url(#lockGradient)" 
                        stroke="url(#accessGradient)" 
                        stroke-width="2"
                        opacity="0.4"/>
                  <line x1="-15" y1="75" x2="15" y2="75" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="-15" y1="85" x2="10" y2="85" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                  <line x1="-15" y1="95" x2="15" y2="95" 
                        :style="{ stroke: 'var(--color-secondary)', strokeWidth: '2', opacity: 0.7 }"/>
                </g>
                
                <!-- Checkmarks on policy documents -->
                <g transform="translate(150, 120)">
                  <!-- Top checkmark -->
                  <circle cx="0" cy="-80" r="12" fill="var(--color-secondary)" opacity="0.2"/>
                  <path d="M -5 -80 L -2 -77 L 5 -85" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                  
                  <!-- Left checkmark -->
                  <circle cx="-80" cy="15" r="12" fill="var(--color-secondary)" opacity="0.2"/>
                  <path d="M -85 15 L -82 18 L -75 10" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                  
                  <!-- Right checkmark -->
                  <circle cx="80" cy="15" r="12" fill="var(--color-secondary)" opacity="0.2"/>
                  <path d="M 75 15 L 78 18 L 85 10" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                  
                  <!-- Bottom checkmark -->
                  <circle cx="0" cy="110" r="12" fill="var(--color-secondary)" opacity="0.2"/>
                  <path d="M -5 110 L -2 113 L 5 105" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                </g>
                
                <!-- Connection lines from policies to lock -->
                <g transform="translate(150, 120)">
                  <line x1="0" y1="-30" x2="0" y2="-10" stroke="url(#accessGradient)" stroke-width="2" opacity="0.4"/>
                  <line x1="-60" y1="15" x2="-25" y2="15" stroke="url(#accessGradient)" stroke-width="2" opacity="0.4"/>
                  <line x1="60" y1="15" x2="25" y2="15" stroke="url(#accessGradient)" stroke-width="2" opacity="0.4"/>
                  <line x1="0" y1="50" x2="0" y2="30" stroke="url(#accessGradient)" stroke-width="2" opacity="0.4"/>
                </g>
                
                <!-- Decorative particles -->
                <circle cx="50" cy="40" r="2" fill="var(--color-primary)" opacity="0.6"/>
                <circle cx="250" cy="60" r="2.5" fill="var(--color-secondary)" opacity="0.5"/>
                <circle cx="80" cy="200" r="2" fill="var(--color-primary)" opacity="0.6"/>
                <circle cx="220" cy="180" r="2" fill="var(--color-secondary)" opacity="0.5"/>
                <circle cx="30" cy="120" r="1.5" fill="var(--color-primary)" opacity="0.7"/>
                <circle cx="270" cy="140" r="1.5" fill="var(--color-secondary)" opacity="0.6"/>
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
        Understand how to configure and manage access control in your applications
      </p>
      
      <div class="explanation-grid">
        <div class="explanation-card">
          <div class="explanation-icon">
            <Shield />
          </div>
          <h3 class="explanation-title">Policies</h3>
          <p class="explanation-text">
            Define RBAC (Role-Based) and ABAC (Attribute-Based) access control policies. 
            Create rules that determine who can access what resources under which conditions. 
            Policies are evaluated by the Policy Decision Point (PDP) to make access decisions.
          </p>
          <button @click="navigateTo('/policies')" class="explanation-link">Manage Policies →</button>
        </div>
        
        <div class="explanation-card">
          <div class="explanation-icon">
            <Folder />
          </div>
          <h3 class="explanation-title">Resources</h3>
          <p class="explanation-text">
            Configure resources with ABAC attributes such as sensitivity level, department, 
            project, and region. Resources are the entities that policies protect, and their 
            attributes are used in policy evaluation.
          </p>
          <button @click="navigateTo('/resources')" class="explanation-link">Manage Resources →</button>
        </div>
        
        <div class="explanation-card">
          <div class="explanation-icon">
            <FileSearch />
          </div>
          <h3 class="explanation-title">Policy Validation</h3>
          <p class="explanation-text">
            Validate policy decisions and test policy configurations. Check for conflicts, 
            analyze coverage, and ensure policies are working correctly before deploying to 
            production.
          </p>
          <button @click="navigateTo('/tests/policy-validation')" class="explanation-link">Validate Policies →</button>
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
            <div class="stat-value">{{ stats.policies || 0 }}</div>
            <div class="stat-label">Policies</div>
          </div>
        </div>
        <div class="stat-card">
          <Folder class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.resources || 0 }}</div>
            <div class="stat-label">Resources</div>
          </div>
        </div>
        <div class="stat-card">
          <Users class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.users || 0 }}</div>
            <div class="stat-label">Test Users</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Shield, Folder, Users, FileSearch } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Access Control', to: '/access-control' },
];

const stats = ref({
  policies: 0,
  resources: 0,
  users: 0,
});

const navigateTo = (path: string) => {
  router.push(path);
};

const loadStats = async () => {
  try {
    // Load policies count
    const policiesRes = await axios.get('/api/policies');
    stats.value.policies = policiesRes.data?.length || 0;
    
    // Load resources count
    const resourcesRes = await axios.get('/api/resources');
    stats.value.resources = resourcesRes.data?.length || 0;
    
    // Load test users count (if available)
    // stats.value.users = ...;
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.access-control-overview-page {
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
  gap: 64px;
  align-items: center;
}

.hero-text {
  flex: 1;
}

.hero-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
  line-height: 1.1;
  letter-spacing: -1px;
}

.hero-subtitle {
  display: block;
  font-size: var(--font-size-2xl);
  margin-top: var(--spacing-md);
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
  gap: 16px;
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
  background: var(--color-info-bg);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: var(--border-color-primary-active);
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

.access-control-svg {
  width: 100%;
  height: auto;
}

.how-it-works-section {
  margin-bottom: 3rem;
}

.section-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.section-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  margin-bottom: 2rem;
}

.explanation-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
}

.explanation-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: 1.5rem;
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
  margin-bottom: var(--spacing-md);
}

.explanation-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: 0.75rem;
}

.explanation-text {
  font-size: 0.95rem;
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin-bottom: var(--spacing-md);
}

.explanation-link {
  color: var(--color-primary);
  font-size: var(--font-size-sm);
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
  margin-bottom: 3rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.stat-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
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
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  line-height: 1;
  margin-bottom: 0.25rem;
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
    font-size: 2rem;
  }
  
  .hero-visual {
    order: -1;
  }
}
</style>

