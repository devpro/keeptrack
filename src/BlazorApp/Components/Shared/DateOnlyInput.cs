using System.Globalization;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Shared parser for a plain HTML date input's onchange value.
/// The HTML spec makes it "yyyy-MM-dd" whatever the browser's locale, so it parses with the invariant culture rather than the current one.
/// Every bound <see cref="DateOnly"/>? field uses it (owned copies, car and house history, video game completion).
/// </summary>
public static class DateOnlyInput
{
    public static DateOnly? Parse(object? value) =>
        DateOnly.TryParse(value?.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date : null;
}
