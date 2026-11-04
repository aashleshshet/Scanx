// Appearance is the only persisted preference; reports and credentials stay in memory.
(() => {
  const key = 'onescanx-appearance';
  const system = window.matchMedia('(prefers-color-scheme: light)');
  let preference;
  try { preference = localStorage.getItem(key); } catch { /* Private browsing may deny storage. */ }
  if (!['light', 'dark'].includes(preference)) preference = null;
  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      const label = `Switch to ${theme === 'dark' ? 'light' : 'dark'} appearance`;
      button.setAttribute('aria-label', label);
      button.setAttribute('title', label);
    });
  }
  function current() { return preference || (system.matches ? 'light' : 'dark'); }
  apply(current());
  document.addEventListener('DOMContentLoaded', () => {
    apply(current());
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.addEventListener('click', () => {
        preference = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(key, preference); } catch { /* Appearance still works this visit. */ }
        apply(preference);
      });
    });
  });
  system.addEventListener('change', () => { if (!preference) apply(current()); });
})();
