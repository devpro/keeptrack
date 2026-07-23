using System.Globalization;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Shared parser for a plain HTML date input's onchange value - always "yyyy-MM-dd" per the HTML spec
/// regardless of the browser's locale, so this always parses with the invariant culture rather than the
/// current one. Used by every owned-copy/car-history/house-history/video-game-completion-style bound
/// <see cref="DateOnly"/>? field instead of duplicating the same TryParse ternary at each call site.
/// </summary>
public static class DateOnlyInput
{
    public static DateOnly? Parse(object? value) =>
        DateOnly.TryParse(value?.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date : null;
}
