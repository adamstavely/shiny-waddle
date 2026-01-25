# Quick Start Guide

## Start the Application

### Step 1: Install Dependencies (if not already done)
```bash
npm run dashboard:install
```

### Step 2: Start the Services

**Open TWO terminal windows:**

#### Terminal 1 - Start API:
```bash
cd dashboard-api
npm run start:dev
```

Wait until you see:
```
🚀 Heimdall Dashboard API running on http://localhost:3001
```

#### Terminal 2 - Start Frontend:
```bash
cd dashboard-frontend
npm run dev
```

Wait until you see:
```
  VITE v5.x.x  ready in xxx ms

  ➜  Local:   http://localhost:5173/
```

### Step 3: Open in Browser

Open http://localhost:5173 in your browser.

## Troubleshooting

### "Connection Refused" Error

1. **Check if services are running:**
   ```bash
   lsof -i :3001  # Should show API process
   lsof -i :5173  # Should show Frontend process
   ```

2. **If ports are in use, kill existing processes:**
   ```bash
   # Find and kill process on port 3001
   lsof -ti :3001 | xargs kill -9
   
   # Find and kill process on port 5173
   lsof -ti :5173 | xargs kill -9
   ```

3. **Check for errors in the terminal:**
   - Look for error messages in the API terminal
   - Look for error messages in the Frontend terminal
   - Common issues:
     - Missing dependencies: Run `npm run dashboard:install`
     - Port conflicts: Kill processes on ports 3001/5173
     - TypeScript errors: Check terminal output

### API Won't Start

1. Check Node.js version (should be v18+):
   ```bash
   node --version
   ```

2. Reinstall dependencies:
   ```bash
   cd dashboard-api
   rm -rf node_modules package-lock.json
   npm install
   ```

3. Check for TypeScript compilation errors:
   ```bash
   cd dashboard-api
   npx tsc --noEmit
   ```

### Frontend Won't Start

1. Reinstall dependencies:
   ```bash
   cd dashboard-frontend
   rm -rf node_modules package-lock.json
   npm install
   ```

2. Check for errors:
   ```bash
   cd dashboard-frontend
   npm run dev
   ```

### Still Having Issues?

1. Make sure you're in the correct directory
2. Check that both terminals show the services are running
3. Try accessing http://localhost:3001 directly to see if API is responding
4. Check browser console (F12) for errors
