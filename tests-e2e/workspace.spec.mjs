import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('evidence workflow, every page, exports, and keyboard navigation', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/workspace/index.html');
  await expect(page.locator('#report-source')).toHaveText('SYNTHETIC DEMO');
  await expect(page.locator('#total-findings')).toHaveText('10');
  for (const name of ['API Inventory', 'New scan', 'Scan history', 'Security Analytics', 'AI Assistant', 'Reports', 'Integrations', 'Settings', 'How to use']) {
    await page.getByRole('navigation').getByRole('button', {name, exact: true}).click();
    await expect(page.locator('#page-title')).not.toBeEmpty();
    await expect(page.locator('body')).not.toContainText('Portfolio Edition');
  }
  await page.getByRole('button', {name:'AI Assistant',exact:true}).click();
  await page.getByLabel('Your question', {exact:true}).fill('Which authorization findings need attention?');
  await page.getByRole('button', {name:'Analyze evidence',exact:true}).click();
  await expect(page.locator('#assistant-answer')).toContainText('EVIDENCE MODE');
  await expect(page.locator('#assistant-answer')).toContainText('Cross-user access');
  await expect(page.locator('#report-source')).toBeVisible();
  await page.getByRole('button',{name:'Reports',exact:true}).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button',{name:'Export CSV',exact:true}).click();
  expect((await download).suggestedFilename()).toBe('onescanx-report.csv');
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByLabel('Find a page').fill('analytics');
  await page.getByRole('dialog').getByRole('button',{name:'Security Analytics',exact:true}).click();
  await page.locator('[data-analytics-level="High"]').click();
  await expect(page.locator('#findings-count')).toHaveText('2');
  expect(errors).toEqual([]);
});

test('mobile navigation, no overflow, and accessibility in both themes', async ({ page }) => {
  await page.setViewportSize({width:390,height:844});
  await page.goto('/workspace/index.html');
  await expect(page.locator('#total-findings')).toHaveText('10');
  await page.getByRole('button',{name:'More workspace pages'}).click();
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Platform session',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  for(const theme of ['dark','light']) {
    if(theme==='light') await page.locator('[data-theme-toggle]').click();
    const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
    expect(result.violations).toEqual([]);
  }
});
