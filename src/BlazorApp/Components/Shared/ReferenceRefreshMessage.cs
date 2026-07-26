namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Shared "check for reference match" result message for every reference-linked detail page's refresh-reference
/// button (Movie/TvShow/Book/Album/VideoGame) - keeps the message/style rule in one place instead of duplicating
/// the same four-way outcome across five detail pages.
/// </summary>
public static class ReferenceRefreshMessage
{
    public static (string Message, string Style) Compute(string? previousReferenceId, string? newReferenceId)
    {
        if (string.IsNullOrEmpty(newReferenceId))
        {
            return string.IsNullOrEmpty(previousReferenceId)
                ? ("No match found", "neutral")
                : ("Unlinked - no match", "danger");
        }

        return newReferenceId == previousReferenceId
            ? ("Already linked", "neutral")
            : ("Linked!", "success");
    }
}
