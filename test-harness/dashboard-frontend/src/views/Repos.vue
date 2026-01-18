<template>
  <div class="repos">
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Repositories
              <span class="hero-subtitle">Version Control Integration</span>
            </h1>
            <p class="hero-description">
              Connect your Git repositories to Heimdall for seamless security testing 
              and compliance validation. Monitor code changes, track security policies 
              across branches, and ensure every commit meets your security standards.
            </p>
            <div class="hero-actions">
              <router-link to="/admin/integrations" class="btn-primary">Connect Repository</router-link>
              <router-link to="/insights" class="btn-secondary">View Status</router-link>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 400 300" class="repo-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="repoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="repoGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.6 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.4 }" />
                  </linearGradient>
                </defs>
                
                <!-- Main repository icon -->
                <g class="repo-main" transform="translate(200, 100)">
                  <!-- Branch structure -->
                  <path d="M 0 -60 Q -40 -40 -60 0 Q -40 40 0 60 Q 40 40 60 0 Q 40 -40 0 -60" 
                        fill="url(#repoGradient)" 
                        opacity="0.2" 
                        stroke="url(#repoGradient)" 
                        stroke-width="2"/>
                  
                  <!-- Central circle -->
                  <circle cx="0" cy="0" r="35" fill="url(#repoGradient)" opacity="0.4" stroke="url(#repoGradient)" stroke-width="2"/>
                  <circle cx="0" cy="0" r="25" fill="url(#repoGradient)" opacity="0.6"/>
                  
                  <!-- Git branch symbol -->
                  <path d="M -15 -10 L -5 -10 L -5 -5 L 5 -5 L 5 5 L -5 5 L -5 10 L -15 10 Z" 
                        fill="#ffffff" 
                        opacity="0.9"/>
                  <circle cx="-10" cy="-10" r="3" fill="#00f2fe"/>
                  <circle cx="0" cy="0" r="3" fill="#4facfe"/>
                  <circle cx="-10" cy="10" r="3" fill="#00f2fe"/>
                </g>
                
                <!-- Branch indicators -->
                <g class="branch-indicators">
                  <!-- Main branch -->
                  <line x1="200" y1="50" x2="200" y2="70" stroke="url(#repoGradient)" stroke-width="3" opacity="0.7"/>
                  <circle cx="200" cy="45" r="5" fill="#00f2fe" opacity="0.8"/>
                  <text x="200" y="40" text-anchor="middle" fill="#4facfe" font-size="12" font-weight="600">main</text>
                  
                  <!-- Feature branch 1 -->
                  <line x1="120" y1="100" x2="150" y2="100" stroke="url(#repoGradientDark)" stroke-width="2" opacity="0.5"/>
                  <circle cx="110" cy="100" r="4" fill="#4facfe" opacity="0.7"/>
                  <text x="110" y="95" text-anchor="middle" fill="#4facfe" font-size="10" font-weight="500">feature</text>
                  
                  <!-- Feature branch 2 -->
                  <line x1="280" y1="100" x2="250" y2="100" stroke="url(#repoGradientDark)" stroke-width="2" opacity="0.5"/>
                  <circle cx="290" cy="100" r="4" fill="#4facfe" opacity="0.7"/>
                  <text x="290" y="95" text-anchor="middle" fill="#4facfe" font-size="10" font-weight="500">develop</text>
                  
                  <!-- Commit nodes -->
                  <circle cx="200" cy="150" r="4" fill="#00f2fe" opacity="0.8"/>
                  <circle cx="200" cy="180" r="4" fill="#00f2fe" opacity="0.7"/>
                  <circle cx="200" cy="210" r="4" fill="#00f2fe" opacity="0.6"/>
                  
                  <!-- Commit lines -->
                  <line x1="200" y1="154" x2="200" y2="176" stroke="url(#repoGradient)" stroke-width="2" opacity="0.5"/>
                  <line x1="200" y1="184" x2="200" y2="206" stroke="url(#repoGradient)" stroke-width="2" opacity="0.5"/>
                  
                  <!-- Security check indicators -->
                  <g class="security-checks" transform="translate(200, 240)">
                    <circle cx="-20" cy="0" r="6" fill="#00f2fe" opacity="0.8"/>
                    <path d="M -23 -2 L -21 0 L -17 -4" stroke="#0f1419" stroke-width="2" fill="none" stroke-linecap="round"/>
                    
                    <circle cx="0" cy="0" r="6" fill="#00f2fe" opacity="0.8"/>
                    <path d="M -3 -2 L -1 0 L 3 -4" stroke="#0f1419" stroke-width="2" fill="none" stroke-linecap="round"/>
                    
                    <circle cx="20" cy="0" r="6" fill="#00f2fe" opacity="0.8"/>
                    <path d="M 17 -2 L 19 0 L 23 -4" stroke="#0f1419" stroke-width="2" fill="none" stroke-linecap="round"/>
                  </g>
                </g>
                
                <!-- Accent elements -->
                <circle cx="80" cy="150" r="3" fill="#4facfe" opacity="0.6"/>
                <circle cx="320" cy="150" r="3" fill="#4facfe" opacity="0.6"/>
                <circle cx="150" cy="220" r="2.5" fill="#00f2fe" opacity="0.7"/>
                <circle cx="250" cy="220" r="2.5" fill="#00f2fe" opacity="0.7"/>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Features Section -->
    <div class="features-section">
      <h2 class="section-title">Repository Features</h2>
      <div class="features-grid">
        <div class="feature-card">
          <div class="feature-icon">
            <GitBranch />
          </div>
          <h3 class="feature-title">Branch Monitoring</h3>
          <p class="feature-description">
            Track security policies and compliance across all branches. 
            Get notified when security configurations change.
          </p>
        </div>
        
        <div class="feature-card">
          <div class="feature-icon">
            <GitCommit />
          </div>
          <h3 class="feature-title">Commit Validation</h3>
          <p class="feature-description">
            Automatically validate security policies on every commit. 
            Block merges that violate compliance requirements.
          </p>
        </div>
        
        <div class="feature-card">
          <div class="feature-icon">
            <Shield />
          </div>
          <h3 class="feature-title">Security Gates</h3>
          <p class="feature-description">
            Integrate with CI/CD pipelines to enforce security gates. 
            Prevent deployment of non-compliant code.
          </p>
        </div>
        
        <div class="feature-card">
          <div class="feature-icon">
            <FileCode />
          </div>
          <h3 class="feature-title">Policy as Code</h3>
          <p class="feature-description">
            Define security policies alongside your code. Version control 
            your security requirements with your application.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { GitBranch, GitCommit, Shield, FileCode } from 'lucide-vue-next';
</script>

<style scoped>
.repos {
  width: 100%;
  min-height: calc(100vh - 60px);
  background: transparent;
  padding: 0;
}

.hero-section {
  max-width: 1400px;
  margin: 48px auto 80px;
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
  display: flex;
  align-items: center;
  gap: 64px;
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
  font-size: 1.25rem;
  color: #a0aec0;
  line-height: 1.6;
  max-width: 600px;
  margin-bottom: 32px;
}

.hero-actions {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.btn-primary,
.btn-secondary {
  padding: 14px 28px;
  border-radius: 12px;
  font-weight: 600;
  font-size: 1rem;
  text-decoration: none;
  transition: all 0.2s;
  display: inline-block;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  background: transparent;
  color: #4facfe;
  border: 2px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.hero-visual {
  flex-shrink: 0;
  display: none;
}

.svg-container {
  width: 500px;
  height: 400px;
  min-width: 500px;
  position: relative;
}

.repo-svg {
  width: 100%;
  height: 100%;
  display: block;
  filter: drop-shadow(0 8px 24px rgba(79, 172, 254, 0.3));
}

@media (min-width: 1024px) {
  .hero-visual {
    display: block;
  }
  
  .hero-title {
    font-size: 5rem;
  }
  
  .hero-subtitle {
    font-size: 2.5rem;
  }
}

.features-section {
  max-width: 1400px;
  margin: 0 auto;
}

.section-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 48px;
  text-align: left;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
}

.feature-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 32px;
  transition: all 0.3s;
}

.feature-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.feature-icon {
  width: 64px;
  height: 64px;
  margin-bottom: 20px;
  color: #4facfe;
}

.feature-icon :deep(svg) {
  width: 100%;
  height: 100%;
}

.feature-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 12px;
}

.feature-description {
  font-size: 1rem;
  color: #a0aec0;
  line-height: 1.6;
}
</style>

