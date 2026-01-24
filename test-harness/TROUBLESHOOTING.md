# Troubleshooting Guide

## "Connection Refused" Error

If you see "localhost refused to connect", the services aren't running. Follow these steps:

### Step 1: Start the API

```bash
cd test-harness/dashboard-api
npm run start:dev
```

**Wait for this message:**
```
🚀 Heimdall Dashboard API running on http://localhost:3001
```

### Step 2: Start the Frontend (in a new terminal)

```bash
cd test-harness/dashboard-frontend
npm run dev
```

**Wait for this message:**
```
  VITE v5.x.x  ready in xxx ms
  ➜  Local:   http://localhost:5173/
```

### Step 3: Open Browser

Open http://localhost:5173

## Common Issues

### API Won't Start - Module Not Found Errors

If you see errors like:
```
Error: Cannot find module '../../../../core/types'
```

**Solution:** The import paths have been fixed. If you still see this:

1. Make sure you're in the `dashboard-api` directory
2. Try reinstalling dependencies:
   ```bash
   cd test-harness/dashboard-api
   rm -rf node_modules package-lock.json
   npm install
   ```

### Port Already in Use

**Kill processes on ports 3001 and 5173:**
```bash
# Kill process on port 3001
lsof -ti :3001 | xargs kill -9

# Kill process on port 5173
lsof -ti :5173 | xargs kill -9
```

### Check if Services are Running

```bash
# Check API
lsof -i :3001

# Check Frontend
lsof -i :5173
```

### Still Having Issues?

1. Make sure Node.js version is 18+:
   ```bash
   node --version
   ```

2. Reinstall all dependencies:
   ```bash
   cd test-harness
   npm run dashboard:install
   ```

3. Check for TypeScript errors:
   ```bash
   cd test-harness/dashboard-api
   npx tsc --noEmit
   ```
