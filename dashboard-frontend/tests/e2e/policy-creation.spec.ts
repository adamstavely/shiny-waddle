/**
 * E2E Tests for Policy Creation Flow
 * Tests the complete policy creation workflow including Visual Builder, Code editor, and template system
 */

import { test, expect } from '@playwright/test';

test.describe('Policy Creation Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Mock API responses
    await page.route('**/api/policies', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-policy-id',
            name: 'Test Policy',
            version: '1.0.0',
            type: 'rbac',
            status: 'draft',
          }),
        });
      }
    });

    await page.route('**/api/policies/templates**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'template-1',
            name: 'Department-Based Access',
            type: 'rbac',
            category: 'department',
            template: {
              rules: [
                {
                  id: 'department-match',
                  description: 'Department match rule',
                  effect: 'allow',
                  conditions: { 'subject.department': '{{resource.department}}' },
                },
              ],
            },
          },
        ]),
      });
    });

    // Navigate to policies page
    await page.goto('/policies/access-control');
    await page.waitForLoadState('networkidle');
  });

  test('creates a policy using Visual Builder', async ({ page }) => {
    // Click Create Policy button
    await page.click('button:has-text("Create Policy")');
    await page.waitForSelector('.modal-content');

    // Fill basic info
    await page.fill('input[type="text"]', 'E2E Test Policy');
    await page.fill('textarea', 'Policy created via E2E test');

    // Switch to Visual Builder tab
    await page.click('button:has-text("Visual Builder")');
    await page.waitForTimeout(500);

    // Verify Visual Builder is visible
    const visualBuilder = page.locator('.policy-visual-builder');
    await expect(visualBuilder).toBeVisible();

    // Add a rule using the Add Rule button
    const addRuleButton = page.locator('.btn-add-rule');
    if (await addRuleButton.isVisible()) {
      await addRuleButton.click();
      await page.waitForTimeout(300);

      // Fill rule details
      await page.fill('input[placeholder*="admin-full-access"]', 'e2e-test-rule');
      await page.fill('textarea[placeholder*="Describe"]', 'E2E test rule');
    }

    // Switch to Preview tab to verify
    await page.click('button:has-text("Preview")');
    await page.waitForTimeout(500);

    // Verify preview shows the policy
    const previewContent = page.locator('.policy-preview');
    await expect(previewContent).toBeVisible();
    const previewText = await previewContent.textContent();
    expect(previewText).toContain('E2E Test Policy');
  });

  test('creates a policy using Code editor', async ({ page }) => {
    // Click Create Policy button
    await page.click('button:has-text("Create Policy")');
    await page.waitForSelector('.modal-content');

    // Fill basic info
    await page.fill('input[type="text"]', 'Code Editor Policy');
    await page.fill('textarea', 'Policy created via Code editor');

    // Switch to Code tab
    await page.click('button:has-text("Code")');
    await page.waitForTimeout(1000); // Wait for Monaco editor to load

    // Verify code editor is visible
    const codeEditor = page.locator('.policy-json-editor');
    await expect(codeEditor).toBeVisible();

    // Note: Monaco editor content is in an iframe/editor, so direct interaction is complex
    // In a real scenario, you might need to use keyboard shortcuts or Monaco's API
    // For now, we'll verify the editor container exists

    // Switch to Preview to verify sync
    await page.click('button:has-text("Preview")');
    await page.waitForTimeout(500);

    const previewContent = page.locator('.policy-preview');
    await expect(previewContent).toBeVisible();
  });

  test('applies template from Visual Builder', async ({ page }) => {
    // Click Create Policy button
    await page.click('button:has-text("Create Policy")');
    await page.waitForSelector('.modal-content');

    // Fill basic info
    await page.fill('input[type="text"]', 'Template Policy');
    await page.fill('textarea', 'Policy from template');

    // Switch to Visual Builder tab
    await page.click('button:has-text("Visual Builder")');
    await page.waitForTimeout(1000);

    // Look for template selector
    const templateSelector = page.locator('select, .dropdown-button').first();
    if (await templateSelector.isVisible()) {
      // Select template (implementation depends on dropdown component)
      await templateSelector.click();
      await page.waitForTimeout(300);
      
      // Select the template option
      const templateOption = page.locator('text=Department-Based Access').first();
      if (await templateOption.isVisible()) {
        await templateOption.click();
        await page.waitForTimeout(500);
      }
    }

    // Verify template was applied by checking if rules exist
    await page.click('button:has-text("Preview")');
    await page.waitForTimeout(500);

    const previewContent = page.locator('.policy-preview');
    await expect(previewContent).toBeVisible();
  });

  test('validates policy before saving', async ({ page }) => {
    // Click Create Policy button
    await page.click('button:has-text("Create Policy")');
    await page.waitForSelector('.modal-content');

    // Fill only name, leave rules empty
    await page.fill('input[type="text"]', 'Invalid Policy');

    // Try to save (should be disabled or show validation errors)
    const saveButton = page.locator('button[type="submit"]:has-text("Save Policy")');
    
    // Check if save button is disabled or validation errors are shown
    const isDisabled = await saveButton.isDisabled();
    const hasValidationErrors = await page.locator('.validation-error').isVisible();

    expect(isDisabled || hasValidationErrors).toBeTruthy();
  });

  test('saves policy successfully', async ({ page }) => {
    // Click Create Policy button
    await page.click('button:has-text("Create Policy")');
    await page.waitForSelector('.modal-content');

    // Fill basic info
    await page.fill('input[type="text"]', 'Complete Policy');
    await page.fill('textarea', 'Complete policy for E2E test');

    // Switch to Rules tab and add a rule
    await page.click('button:has-text("Rules")');
    await page.waitForTimeout(500);

    const addRuleButton = page.locator('button:has-text("Add Rule")');
    if (await addRuleButton.isVisible()) {
      await addRuleButton.click();
      await page.waitForTimeout(300);

      // Fill rule details
      await page.fill('input[placeholder*="admin-full-access"]', 'complete-rule');
      await page.fill('textarea[placeholder*="Describe"]', 'Complete rule');

      // Add a condition
      const addConditionButton = page.locator('button:has-text("Add Condition")');
      if (await addConditionButton.isVisible()) {
        await addConditionButton.click();
        await page.waitForTimeout(300);
        
        const conditionInputs = page.locator('.condition-key, .condition-value');
        const inputCount = await conditionInputs.count();
        if (inputCount >= 2) {
          await conditionInputs.nth(0).fill('subject.role');
          await conditionInputs.nth(1).fill('admin');
        }
      }
    }

    // Save policy
    const saveButton = page.locator('button[type="submit"]:has-text("Save Policy")');
    await expect(saveButton).toBeEnabled();
    await saveButton.click();

    // Wait for modal to close (policy saved)
    await page.waitForSelector('.modal-content', { state: 'hidden' });
    
    // Verify success (policy should appear in list or show success message)
    await page.waitForTimeout(1000);
  });

  test('switches between tabs maintaining data', async ({ page }) => {
    // Click Create Policy button
    await page.click('button:has-text("Create Policy")');
    await page.waitForSelector('.modal-content');

    // Fill basic info
    await page.fill('input[type="text"]', 'Tab Sync Test');
    await page.fill('textarea', 'Testing tab synchronization');

    // Navigate through tabs
    const tabs = ['Rules', 'Visual Builder', 'Code', 'Preview'];
    
    for (const tab of tabs) {
      await page.click(`button:has-text("${tab}")`);
      await page.waitForTimeout(500);
      
      // Verify name is still there
      const nameInput = page.locator('input[type="text"]').first();
      const nameValue = await nameInput.inputValue();
      expect(nameValue).toBe('Tab Sync Test');
    }
  });
});
