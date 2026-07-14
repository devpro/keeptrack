function ktApplyTheme() {
    var stored = localStorage.getItem('kt-theme');
    var theme = stored || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-bs-theme', theme);
}

// runs immediately, before CSS paints, so the very first page load never flashes the wrong theme
ktApplyTheme();

function ktToggleTheme() {
    var current = document.documentElement.getAttribute('data-bs-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-bs-theme', next);
    localStorage.setItem('kt-theme', next);
}
