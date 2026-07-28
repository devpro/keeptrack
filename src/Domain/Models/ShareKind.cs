namespace Keeptrack.Domain.Models;

/// <summary>
/// Whether a <see cref="ShareCategory"/> is ordinary media (viewable and copyable into the recipient's
/// own collection) or personal/sensitive data (view-only, never copyable). Derived from the category by
/// <see cref="Services.ShareCategoryClassifier"/> - the single place that rule lives - never stored.
/// </summary>
public enum ShareKind
{
    Media,
    Personal
}
