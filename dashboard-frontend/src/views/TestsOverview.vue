<template>
  <div class="tests-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Test Management
              <span class="hero-subtitle">Comprehensive Testing Framework</span>
            </h1>
            <p class="hero-description">
              Organize and manage your security tests through a hierarchical structure of tests, 
              suites, harnesses, and batteries. Track results, manage findings, and ensure continuous 
              compliance with automated testing workflows.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/tests/suites')" class="btn-primary">View Test Suites</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 300 240" class="test-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="testGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="testGradientLight" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.3 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.3 }" />
                  </linearGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                </defs>
                
                <!-- Main test tube/flask -->
                <g transform="translate(150, 120)">
                  <!-- Flask body -->
                  <path d="M -40 40 Q -40 20 -20 20 L 20 20 Q 40 20 40 40 L 40 100 Q 40 120 20 120 L -20 120 Q -40 120 -40 100 Z" 
                        fill="url(#testGradientLight)" 
                        stroke="url(#testGradient)" 
                        stroke-width="2.5"
                        opacity="0.4"/>
                  
                  <!-- Flask neck -->
                  <rect x="-15" y="10" width="30" height="20" rx="3" 
                        fill="url(#testGradientLight)" 
                        stroke="url(#testGradient)" 
                        stroke-width="2"
                        opacity="0.4"/>
                  
                  <!-- Test liquid levels -->
                  <rect x="-35" y="80" width="70" height="35" rx="2" 
                        fill="url(#testGradient)" 
                        opacity="0.6"/>
                  <rect x="-35" y="60" width="70" height="20" rx="2" 
                        fill="url(#testGradient)" 
                        opacity="0.4"/>
                  
                  <!-- Bubbles in liquid -->
                  <circle cx="-20" cy="70" r="3" fill="var(--color-secondary)" opacity="0.8"/>
                  <circle cx="10" cy="75" r="2.5" fill="var(--color-secondary)" opacity="0.7"/>
                  <circle cx="20" cy="65" r="2" fill="var(--color-secondary)" opacity="0.6"/>
                  <circle cx="-10" cy="85" r="2" fill="var(--color-secondary)" opacity="0.5"/>
                </g>
                
                <!-- Test checkmarks around the flask -->
                <g transform="translate(150, 120)">
                  <!-- Top checkmark -->
                  <circle cx="0" cy="-50" r="18" fill="url(#testGradientLight)" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                  <path d="M -8 -50 L -3 -45 L 8 -55" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                  
                  <!-- Left checkmark -->
                  <circle cx="-60" cy="20" r="18" fill="url(#testGradientLight)" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                  <path d="M -68 20 L -63 25 L -52 15" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                  
                  <!-- Right checkmark -->
                  <circle cx="60" cy="20" r="18" fill="url(#testGradientLight)" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                  <path d="M 52 20 L 57 25 L 68 15" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                  
                  <!-- Bottom checkmark -->
                  <circle cx="0" cy="90" r="18" fill="url(#testGradientLight)" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                  <path d="M -8 90 L -3 95 L 8 85" 
                        stroke="var(--color-secondary)" 
                        stroke-width="3" 
                        fill="none" 
                        stroke-linecap="round" 
                        stroke-linejoin="round"
                        filter="url(#glow)"/>
                </g>
                
                <!-- Decorative particles/flakes -->
                <circle cx="50" cy="40" r="2" fill="var(--color-primary)" opacity="0.6"/>
                <circle cx="250" cy="60" r="2.5" fill="var(--color-secondary)" opacity="0.5"/>
                <circle cx="80" cy="180" r="2" fill="var(--color-primary)" opacity="0.6"/>
                <circle cx="220" cy="200" r="2" fill="var(--color-secondary)" opacity="0.5"/>
                <circle cx="30" cy="120" r="1.5" fill="var(--color-primary)" opacity="0.7"/>
                <circle cx="270" cy="140" r="1.5" fill="var(--color-secondary)" opacity="0.6"/>
                
                <!-- Connection lines between checkmarks -->
                <line x1="150" y1="70" x2="90" y2="120" stroke="url(#testGradient)" stroke-width="1.5" opacity="0.3"/>
                <line x1="150" y1="70" x2="210" y2="120" stroke="url(#testGradient)" stroke-width="1.5" opacity="0.3"/>
                <line x1="150" y1="210" x2="90" y2="120" stroke="url(#testGradient)" stroke-width="1.5" opacity="0.3"/>
                <line x1="150" y1="210" x2="210" y2="120" stroke="url(#testGradient)" stroke-width="1.5" opacity="0.3"/>
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
        Understand the relationship between test configurations, suites, harnesses, and batteries
      </p>
      
      <!-- Relationship Diagram -->
      <div class="diagram-container">
        <svg viewBox="0 0 1000 600" class="hierarchy-diagram">
          <!-- Background -->
          <rect width="1000" height="600" fill="transparent" />
          
          <!-- Level 1: Applications (Infrastructure) -->
          <g class="diagram-level" data-level="applications">
            <rect x="50" y="50" width="180" height="100" rx="8" class="diagram-box config-box" />
            <text x="140" y="95" text-anchor="middle" class="diagram-title">Applications</text>
            <text x="140" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.applications }}</text>
          </g>
          
          <!-- Level 2: Individual Tests -->
          <g class="diagram-level" data-level="tests">
            <rect x="300" y="50" width="180" height="100" rx="8" class="diagram-box test-box" />
            <text x="390" y="95" text-anchor="middle" class="diagram-title">Individual Tests</text>
            <text x="390" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.tests }}</text>
          </g>
          
          <!-- Level 3: Test Suites -->
          <g class="diagram-level" data-level="suites">
            <rect x="550" y="50" width="180" height="100" rx="8" class="diagram-box suite-box" />
            <text x="640" y="95" text-anchor="middle" class="diagram-title">Test Suites</text>
            <text x="640" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.suites }}</text>
          </g>
          
          <!-- Level 4: Test Harnesses -->
          <g class="diagram-level" data-level="harnesses">
            <rect x="300" y="250" width="180" height="100" rx="8" class="diagram-box harness-box" />
            <text x="390" y="295" text-anchor="middle" class="diagram-title">Test Harnesses</text>
            <text x="390" y="315" text-anchor="middle" class="diagram-subtitle">{{ stats.harnesses }}</text>
          </g>
          
          <!-- Level 5: Test Batteries -->
          <g class="diagram-level" data-level="batteries">
            <rect x="550" y="250" width="180" height="100" rx="8" class="diagram-box battery-box" />
            <text x="640" y="295" text-anchor="middle" class="diagram-title">Test Batteries</text>
            <text x="640" y="315" text-anchor="middle" class="diagram-subtitle">{{ stats.batteries }}</text>
          </g>
          
          <!-- Arrows -->
          <!-- Applications → Tests (infrastructure used by tests) -->
          <path d="M 230 100 L 300 100" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Tests → Suites -->
          <path d="M 480 100 L 550 100" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Suites → Harnesses -->
          <path d="M 640 150 L 390 250" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Harnesses → Batteries -->
          <path d="M 480 300 L 550 300" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Arrow marker definition -->
          <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
              <polygon points="0 0, 10 3, 0 6" class="arrow-fill" />
            </marker>
          </defs>
        </svg>
      </div>
      
      <!-- Relationship Explanation -->
      <div class="relationship-explanation">
        <div class="explanation-steps">
          <div class="step">
            <div class="step-number">1</div>
            <div class="step-content">
              <strong>Application Infrastructure</strong> defines what infrastructure exists (databases, networks, APIs)
            </div>
          </div>
          <div class="step">
            <div class="step-number">2</div>
            <div class="step-content">
              <strong>Individual Tests</strong> validate specific security requirements using infrastructure and policies
            </div>
          </div>
          <div class="step">
            <div class="step-number">3</div>
            <div class="step-content">
              <strong>Test Suites</strong> group related tests together for organized execution
            </div>
          </div>
          <div class="step">
            <div class="step-number">4</div>
            <div class="step-content">
              <strong>Test Harnesses</strong> collect suites and assign them to applications
            </div>
          </div>
          <div class="step">
            <div class="step-number">5</div>
            <div class="step-content">
              <strong>Test Batteries</strong> execute multiple harnesses together with execution configuration
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
          <Settings class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.applications }}</div>
            <div class="stat-label">Applications</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/suites')">
          <List class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.suites }}</div>
            <div class="stat-label">Test Suites</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/harnesses')">
          <Layers class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.harnesses }}</div>
            <div class="stat-label">Test Harnesses</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/batteries')">
          <Battery class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.batteries }}</div>
            <div class="stat-label">Test Batteries</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/findings')">
          <AlertCircle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.findings }}</div>
            <div class="stat-label">Active Findings</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="actions-section">
      <h2 class="section-title">Quick Actions</h2>
      <div class="actions-grid">
        <button @click="navigateTo('/tests/batteries')" class="action-card">
          <Battery class="action-icon" />
          <span>View Test Batteries</span>
        </button>
        <button @click="navigateTo('/tests/harnesses')" class="action-card">
          <Layers class="action-icon" />
          <span>View Test Harnesses</span>
        </button>
        <button @click="navigateTo('/tests/suites')" class="action-card">
          <List class="action-icon" />
          <span>View Test Suites</span>
        </button>
        <button @click="navigateTo('/tests/findings')" class="action-card">
          <AlertCircle class="action-icon" />
          <span>View Findings</span>
        </button>
        <button @click="navigateTo('/tests/suites/builder')" class="action-card">
          <Plus class="action-icon" />
          <span>Create Test Suite</span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Battery,
  Layers,
  List,
  AlertCircle,
  Settings,
  Plus
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' }
];

const stats = ref({
  applications: 0,
  tests: 0,
  suites: 0,
  harnesses: 0,
  batteries: 0,
  findings: 0
});

const loadStats = async () => {
  try {
    const [configsRes, suitesRes, harnessesRes, batteriesRes, resultsRes] = await Promise.all([
      // Test configurations removed - infrastructure is now part of applications
      Promise.resolve({ data: [] }),
      axios.get('/api/v1/test-suites').catch(() => ({ data: [] })),
      axios.get('/api/v1/test-harnesses').catch(() => ({ data: [] })),
      axios.get('/api/v1/test-batteries').catch(() => ({ data: [] })),
      axios.get('/api/v1/test-results?limit=1000').catch(() => ({ data: [] }))
    ]);
    
    // Load applications count for infrastructure stat
    const appsRes = await axios.get('/api/v1/applications').catch(() => ({ data: [] }));
    
    stats.value = {
      applications: appsRes.data?.length || 0,
      tests: 0, // Will be loaded separately if needed
      suites: suitesRes.data?.length || 0,
      harnesses: harnessesRes.data?.length || 0,
      batteries: batteriesRes.data?.length || 0,
      findings: resultsRes.data?.filter((r: any) => !r.passed || r.status === 'failed').length || 0
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
.tests-overview-page {
  padding: var(--spacing-xl);
  max-width: 1400px;
  margin: 0 auto;
}

/* Hero Section - matching Homepage style */
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
  inset: 0;
  opacity: 0.1;
  background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
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

.test-svg {
  width: 100%;
  height: auto;
}

/* How It Works Section */
.how-it-works-section {
  margin-bottom: var(--spacing-2xl);
}

.section-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.section-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xl);
}

.diagram-container {
  display: flex;
  justify-content: center;
  margin: var(--spacing-xl) 0;
  padding: var(--spacing-xl);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-lg);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.hierarchy-diagram {
  width: 100%;
  max-width: 1000px;
  height: auto;
}

.diagram-box {
  fill: rgba(79, 172, 254, 0.15);
  stroke: rgba(79, 172, 254, 0.5);
  stroke-width: var(--border-width-medium);
  transition: var(--transition-all);
}

.diagram-box:hover {
  fill: rgba(79, 172, 254, 0.25);
  stroke: rgba(79, 172, 254, 0.8);
}

.config-box {
  fill: rgba(79, 172, 254, 0.15);
}

.test-box {
  fill: rgba(0, 242, 254, 0.15);
}

.suite-box {
  fill: rgba(139, 92, 246, 0.15);
}

.harness-box {
  fill: rgba(236, 72, 153, 0.15);
}

.battery-box {
  fill: rgba(251, 191, 36, 0.15);
}

.diagram-title {
  fill: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
}

.diagram-subtitle {
  fill: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.diagram-arrow {
  stroke: rgba(79, 172, 254, 0.6);
  stroke-width: 2;
  fill: none;
}

.arrow-fill {
  fill: rgba(79, 172, 254, 0.6);
}

.relationship-explanation {
  margin-top: 3rem;
  padding-top: var(--spacing-xl);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.explanation-steps {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--spacing-lg);
}

.step {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
}

.step-number {
  width: 32px;
  height: 32px;
  border-radius: var(--border-radius-full);
  background: var(--gradient-primary);
  color: var(--color-text-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: var(--font-weight-semibold);
  flex-shrink: 0;
}

.step-content {
  flex: 1;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  line-height: 1.5;
}

.step-content strong {
  color: var(--color-text-primary);
  display: block;
  margin-bottom: 0.25rem;
}

/* Quick Stats Section */
.stats-section {
  margin-bottom: 4rem;
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
