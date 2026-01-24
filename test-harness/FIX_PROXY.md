# Fix: Frontend Can't Connect to API

## Issue
The frontend is running but API requests are failing with `ERR_CONNECTION_REFUSED`.

## Solution

The Vite proxy configuration has been updated. **You need to restart the frontend** for the changes to take effect.

### Steps:

1. **Stop the frontend** (Ctrl+C in the terminal where it's running)

2. **Restart the frontend:**
   ```bash
   cd test-harness/dashboard-frontend
   npm run dev
   ```

3. **Refresh your browser** (hard refresh: Cmd+Shift+R on Mac, Ctrl+Shift+R on Windows/Linux)

## What Was Fixed

- Added `host: true` to allow external connections
- Added `secure: false` for local development
- Added `ws: true` to enable WebSocket proxying (for HMR)

## Verify It's Working

After restarting, check the browser console - you should no longer see `ERR_CONNECTION_REFUSED` errors.

The API is running correctly on port 3001, so once the frontend proxy is working, everything should connect properly.
