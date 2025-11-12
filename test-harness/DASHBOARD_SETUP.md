# Heimdall Dashboard Setup Guide

The Heimdall dashboard has been rewritten with:
- **Backend**: NestJS (Node.js framework)
- **Frontend**: Vue.js 3 with Composition API

## Quick Start

### 1. Install Dependencies

From the `test-harness` directory:

```bash
npm run dashboard:install
```

Or manually:

```bash
cd dashboard-api && npm install
cd ../dashboard-frontend && npm install
```

### 2. Start the Backend (NestJS API)

In one terminal:

```bash
npm run dashboard:api
```

Or manually:

```bash
cd dashboard-api
npm run start:dev
```

The API will run on **http://localhost:3001**

### 3. Start the Frontend (Vue.js)

In another terminal:

```bash
npm run dashboard:frontend
```

Or manually:

```bash
cd dashboard-frontend
npm run dev
```

The frontend will run on **http://localhost:5173**

## Architecture

### Backend Structure (`dashboard-api/`)

```
dashboard-api/
├── src/
│   ├── main.ts                 # NestJS bootstrap
│   ├── app.module.ts           # Root module
│   └── dashboard/
│       ├── dashboard.module.ts # Dashboard module
│       ├── dashboard.controller.ts # API endpoints
│       └── dashboard.service.ts    # Business logic
├── package.json
└── tsconfig.json
```

**API Endpoints:**
- `GET /api/dashboard-data` - Returns dashboard data (compliance scores, test results)
- `GET /api/reports` - Returns compliance reports

### Frontend Structure (`dashboard-frontend/`)

```
dashboard-frontend/
├── src/
│   ├── main.ts                 # Vue app entry point
│   ├── App.vue                 # Root component
│   ├── style.css               # Global styles
│   └── components/
│       ├── Header.vue          # Dashboard header
│       ├── OverallScore.vue   # Overall compliance score display
│       ├── ScoreCard.vue      # Score cards (by app/team)
│       ├── CategoryScores.vue # Category breakdown with progress bars
│       └── TestResultsTable.vue # Recent test results table
├── index.html
├── vite.config.ts             # Vite configuration
└── package.json
```

## Features

- **Real-time Dashboard**: Auto-refreshes every 30 seconds
- **Responsive Design**: Works on desktop and mobile
- **Component-based**: Modular Vue components
- **Type-safe**: Full TypeScript support
- **Modern Stack**: Vue 3 Composition API + Vite

## Development

### Backend Development

```bash
cd dashboard-api
npm run start:dev  # Watch mode with hot reload
```

### Frontend Development

```bash
cd dashboard-frontend
npm run dev  # Vite dev server with HMR
```

## Production Build

### Backend

```bash
cd dashboard-api
npm run build
npm run start:prod
```

### Frontend

```bash
cd dashboard-frontend
npm run build
# Output in dist/ directory
```

## Troubleshooting

### Port Already in Use

If port 3001 (API) or 5173 (Frontend) is already in use:

- **API**: Set `PORT` environment variable: `PORT=3002 npm run start:dev`
- **Frontend**: Update `vite.config.ts` port setting

### CORS Issues

The API is configured to allow requests from `http://localhost:5173`. If you change the frontend port, update the CORS configuration in `dashboard-api/src/main.ts`.

### No Dashboard Data

If you see sample data, run compliance tests first:

```bash
npm run test:compliance
```

This generates `dashboard-data.json` in the `reports/` directory.

