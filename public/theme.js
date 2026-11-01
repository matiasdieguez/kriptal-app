const THEME_KEY = 'kriptal-theme';

function applyTheme(theme) {
  const selectedTheme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = selectedTheme;
  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) themeColor.content = selectedTheme === 'dark' ? '#121815' : '#f5f1e8';
}

const savedTheme = localStorage.getItem(THEME_KEY);
window.applyKriptalTheme = applyTheme;
applyTheme(savedTheme === 'light' ? 'light' : 'dark');
