# Local Development Setup

This guide will help you run the Heimdall dashboard application locally.

## Prerequisites

- Node.js (v18 or higher recommended)
- npm (comes with Node.js)

## Quick Start

### 1. Install Dependencies

From the root directory (`test-harness/`), run:

```bash
npm run dashboard:install
```

This will install dependencies for both the API and frontend.

Alternatively, you can install them separately:

```bash
# Install API dependencies
cd dashboard-api
npm install

# Install frontend dependencies
cd ../dashboard-frontend
npm install
```

### 2. Start the Application

You have three options:

#### Option A: Start Both Services with Script (Easiest)

From the root directory, run:

```bash
cd test-harness
npm run dashboard:start
```

Or directly:
```bash
cd test-harness
./start-local.sh
```

This will start both the API and frontend in the background. Press Ctrl+C to stop both.

#### Option B: Start Services Separately (Recommended for Development)

From the root directory, you can start both services using the root package.json scripts:

**Terminal 1 - Start API:**
```bash
cd test-harness
npm run dashboard:api
```

**Terminal 2 - Start Frontend:**
```bash
cd test-harness
npm run dashboard:frontend
```

#### Option C: Start Services from Their Directories

**Start API:**
```bash
cd test-harness/dashboard-api
npm run start:dev
```

**Start Frontend:**
```bash
cd test-harness/dashboard-frontend
npm run dev
```

### 3. Access the Application

- **Frontend**: http://localhost:5173
- **API**: http://localhost:3001

The frontend is configured to proxy API requests to the backend automatically.

## Project Structure

```
test-harness/
├── dashboard-api/          # NestJS backend (port 3001)
│   ├── src/
│   └── package.json
├── dashboard-frontend/      # Vue.js frontend (port 5173)
│   ├── src/
│   └── package.json
└── package.json             # Root package with convenience scripts
```

## Troubleshooting

### Port Already in Use

If port 3001 or 5173 is already in use:

**For API (port 3001):**
- Check what's using the port: `lsof -i :3001`
- Kill the process or change the port in `dashboard-api/src/main.ts`

**For Frontend (port 5173):**
- Check what's using the port: `lsof -i :5173`
- Kill the process or change the port in `dashboard-frontend/vite.config.ts`

### API Not Responding

1. Make sure the API is running on port 3001
2. Check the API console for errors
3. Verify the frontend proxy configuration in `dashboard-frontend/vite.config.ts`

### Frontend Can't Connect to API

1. Ensure the API is running before starting the frontend
2. Check that the proxy target in `vite.config.ts` matches the API port (default: 3001)
3. Check browser console for CORS or connection errors

## Development Notes

- The frontend uses Vite's proxy feature to forward `/api/*` requests to the backend
- API runs in development mode with hot-reload enabled
- Frontend runs in development mode with Vite's HMR (Hot Module Replacement)
- Data is stored in JSON files in the `data/` directory at the root level

## Next Steps

Once both services are running:
1. Open http://localhost:5173 in your browser
2. The dashboard should load and connect to the API automatically
3. Start developing!
