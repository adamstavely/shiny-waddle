<template>
  <div class="not-found">
    <div class="not-found-container">
      <!-- Background decoration -->
      <div class="background-decoration" aria-hidden="true">
        <div class="decoration-circle circle-1"></div>
        <div class="decoration-circle circle-2"></div>
        <div class="decoration-circle circle-3"></div>
      </div>

      <!-- Main content -->
      <div class="not-found-content">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <!-- Large 404 number -->
        <div class="error-code" aria-label="Error 404">
          <span class="code-digit" aria-hidden="true">4</span>
          <span class="code-digit" aria-hidden="true">0</span>
          <span class="code-digit" aria-hidden="true">4</span>
        </div>

        <!-- Custom SVG Icon -->
        <div class="error-icon" aria-hidden="true">
          <svg viewBox="0 0 250 200" class="not-found-svg" preserveAspectRatio="xMidYMid meet">
            <defs>
              <linearGradient id="compassGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
              </linearGradient>
            </defs>
            
            <!-- Compass outer ring -->
            <circle 
              cx="125" 
              cy="100" 
              r="70" 
              fill="none" 
              stroke="url(#compassGradient)" 
              stroke-width="3" 
              opacity="0.4"
            />
            
            <!-- Compass inner ring -->
            <circle 
              cx="125" 
              cy="100" 
              r="55" 
              fill="none" 
              stroke="url(#compassGradient)" 
              stroke-width="2" 
              opacity="0.5"
            />
            
            <!-- Compass needle pointing up (North) -->
            <path 
              d="M 125 30 L 135 60 L 125 50 L 115 60 Z" 
              fill="url(#compassGradient)" 
              opacity="0.9"
            />
            
            <!-- Compass needle pointing down (South) -->
            <path 
              d="M 125 170 L 115 140 L 125 150 L 135 140 Z" 
              fill="url(#compassGradient)" 
              opacity="0.6"
            />
            
            <!-- Compass center circle -->
            <circle 
              cx="125" 
              cy="100" 
              r="20" 
              fill="url(#compassGradient)" 
              opacity="0.8"
            />
            
            <!-- Direction markers -->
            <text x="125" y="25" text-anchor="middle" fill="url(#compassGradient)" font-size="16" font-weight="600" opacity="0.8">N</text>
            <text x="125" y="185" text-anchor="middle" fill="url(#compassGradient)" font-size="16" font-weight="600" opacity="0.6">S</text>
            <text x="200" y="105" text-anchor="middle" fill="url(#compassGradient)" font-size="16" font-weight="600" opacity="0.7">E</text>
            <text x="50" y="105" text-anchor="middle" fill="url(#compassGradient)" font-size="16" font-weight="600" opacity="0.7">W</text>
          </svg>
        </div>

        <!-- Title and message -->
        <h1 class="error-title">Page Not Found</h1>
        <p class="error-message">
          The page you're looking for doesn't exist or has been moved.
          <br />
          Let's get you back on track.
        </p>

        <!-- Action buttons -->
        <nav class="error-actions" aria-label="Primary navigation actions">
          <router-link to="/" class="btn-primary" aria-label="Go to home page">
            <Home class="btn-icon" aria-hidden="true" />
            <span>Go Home</span>
          </router-link>
          <button @click="goBack" class="btn-secondary" aria-label="Go back to previous page">
            <ArrowLeft class="btn-icon" aria-hidden="true" />
            <span>Go Back</span>
          </button>
        </nav>

        <!-- Quick links -->
        <nav class="quick-links" aria-label="Quick navigation links">
          <h2 class="quick-links-title">Popular Pages:</h2>
          <ul class="links-grid" role="list">
            <li>
              <router-link to="/violations" class="quick-link" aria-label="Go to Violations page">
                <AlertTriangle class="link-icon" aria-hidden="true" />
                <span>Violations</span>
              </router-link>
            </li>
            <li>
              <router-link to="/policies" class="quick-link" aria-label="Go to Policies page">
                <Shield class="link-icon" aria-hidden="true" />
                <span>Policies</span>
              </router-link>
            </li>
            <li>
              <router-link to="/compliance" class="quick-link" aria-label="Go to Compliance page">
                <FileCheck class="link-icon" aria-hidden="true" />
                <span>Compliance</span>
              </router-link>
            </li>
          </ul>
        </nav>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router';
import { 
  Home, 
  ArrowLeft, 
  BarChart3, 
  AlertTriangle, 
  Shield, 
  FileCheck 
} from 'lucide-vue-next';

const router = useRouter();

const goBack = () => {
  if (window.history.length > 1) {
    router.go(-1);
  } else {
    router.push('/');
  }
};
</script>

<style scoped>
.not-found {
  width: 100%;
  min-height: calc(100vh - 64px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  position: relative;
  overflow: hidden;
}

.not-found-container {
  position: relative;
  max-width: 800px;
  width: 100%;
  z-index: 10;
}

.background-decoration {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.decoration-circle {
  position: absolute;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--color-info-bg) 0%, rgba(0, 242, 254, 0.1) 100%);
  filter: blur(60px);
  animation: float 20s ease-in-out infinite;
}

.circle-1 {
  width: 400px;
  height: 400px;
  top: -200px;
  left: -200px;
  animation-delay: 0s;
}

.circle-2 {
  width: 300px;
  height: 300px;
  bottom: -150px;
  right: -150px;
  animation-delay: 7s;
}

.circle-3 {
  width: 250px;
  height: 250px;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation-delay: 14s;
}

@keyframes float {
  0%, 100% {
    transform: translate(0, 0) scale(1);
    opacity: 0.3;
  }
  50% {
    transform: translate(30px, -30px) scale(1.1);
    opacity: 0.5;
  }
}

.not-found-content {
  position: relative;
  z-index: 10;
  text-align: center;
  background: var(--gradient-card-full);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: 24px;
  padding: var(--spacing-2xl) 64px;
  box-shadow: var(--shadow-xl);
  overflow: hidden;
}

.hero-background {
  position: absolute;
  inset: 0;
  opacity: 0.1;
  background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
  z-index: 1;
}

.error-code,
.error-icon,
.error-title,
.error-message,
.error-actions,
.quick-links {
  position: relative;
  z-index: 10;
}

.error-code {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
  margin-bottom: 32px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.code-digit {
  font-size: 8rem;
  font-weight: 800;
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  line-height: 1;
  text-shadow: 0 0 40px rgba(79, 172, 254, 0.3);
  animation: pulse 2s ease-in-out infinite;
}

.code-digit:nth-child(2) {
  animation-delay: 0.2s;
}

.code-digit:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.8;
    transform: scale(1.05);
  }
}

.error-icon {
  display: flex;
  justify-content: center;
  margin-bottom: 24px;
}

.not-found-svg {
  width: 250px;
  height: 200px;
  filter: drop-shadow(0 8px 24px rgba(79, 172, 254, 0.3));
}


.error-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
  line-height: 1.2;
}

.error-message {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin-bottom: 40px;
  max-width: 500px;
  margin-left: auto;
  margin-right: auto;
}

.error-actions {
  display: flex;
  gap: 16px;
  justify-content: center;
  margin-bottom: 48px;
  flex-wrap: wrap;
}

.btn-primary,
.btn-secondary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 14px 28px;
  border-radius: 12px;
  font-weight: 600;
  font-size: 1rem;
  text-decoration: none;
  transition: all 0.2s;
  border: none;
  cursor: pointer;
  font-family: inherit;
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-secondary {
  background: transparent;
  color: var(--color-primary);
  border: var(--border-width-medium) solid var(--border-color-secondary);
}

.btn-secondary:hover {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
}

.btn-icon {
  width: 20px;
  height: 20px;
}

.quick-links {
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  padding-top: var(--spacing-xl);
}

.quick-links-title {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
  margin-bottom: 16px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-weight: 600;
}

.links-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  max-width: 600px;
  margin: 0 auto;
  list-style: none;
  padding: 0;
}

.links-grid li {
  margin: 0;
}

.quick-link {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  border-radius: 8px;
  background: rgba(79, 172, 254, 0.05);
  border: var(--border-width-thin) solid var(--border-color-muted);
  color: var(--color-text-secondary);
  text-decoration: none;
  transition: var(--transition-all);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}

.quick-link:hover {
  background: var(--color-info-bg);
  border-color: var(--border-color-secondary);
  color: var(--color-primary);
  transform: translateY(-2px);
}

.link-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

/* Responsive design */
@media (max-width: 768px) {
  .not-found {
    padding: 24px 16px;
  }

  .not-found-content {
    padding: 48px 32px;
  }

  .code-digit {
    font-size: 5rem;
  }

  .error-title {
    font-size: 2rem;
  }

  .error-message {
    font-size: 1rem;
  }

  .error-actions {
    flex-direction: column;
    width: 100%;
  }

  .btn-primary,
  .btn-secondary {
    width: 100%;
    justify-content: center;
  }

  .links-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 480px) {
  .code-digit {
    font-size: 4rem;
  }

  .not-found-svg {
    width: 150px;
    height: 150px;
  }

  .error-title {
    font-size: 1.75rem;
  }

  .links-grid {
    grid-template-columns: 1fr;
  }
}
</style>

