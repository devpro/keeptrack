namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// The "check for reference match" result message for every reference-linked detail page (movie, TV show, book, album, video game).
/// The four-way outcome and its style live here once rather than in five detail pages.
/// </summary>
public static class ReferenceRefreshMessage
{
    public static (string Message, string Style) Compute(string? previousReferenceId, string? newReferenceId)
    {
        if (string.IsNullOrEmpty(newReferenceId))
        {
            return string.IsNullOrEmpty(previousReferenceId)
                ? ("No match", "neutral")
                : ("Unlinked", "danger");
        }

        return newReferenceId == previousReferenceId
            ? ("No change", "neutral")
            : ("Linked!", "success");
    }
}
