// JS initializer, auto-detected and loaded by Blazor (file name must match the assembly name).
// Re-applies the theme after enhanced navigation, since data-bs-theme is set by client-side JS
// (theme.js) rather than server-rendered markup, so Blazor's enhanced-navigation DOM diff would
// otherwise drop it whenever it merges in a freshly server-rendered page.
export function afterWebStarted(blazor) {
    blazor.addEventListener('enhancedload', ktApplyTheme);
}
