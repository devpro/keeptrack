using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// The single place the "how is this category presented, and can it be copied" rule lives. Media is a
/// read-only list copyable into the recipient's own collection; ordinary collections (collectibles, gear)
/// are a read-only list but view-only (no shared reference identity to copy); personal data (cars, houses,
/// health) is a read-only detail view and never copyable. Both the copy endpoint's gate and the owner UI's
/// grouping derive from this, so the rule can never drift between them.
/// </summary>
public static class ShareCategoryClassifier
{
    public static ShareKind KindOf(ShareCategory category) => category switch
    {
        ShareCategory.Cars or ShareCategory.Houses or ShareCategory.Health => ShareKind.Personal,
        ShareCategory.Collectibles or ShareCategory.Gears => ShareKind.Collection,
        _ => ShareKind.Media
    };

    /// <summary>Only reference-linked media can be copied; collections and personal data never can.</summary>
    public static bool IsCopyable(ShareCategory category) => KindOf(category) == ShareKind.Media;
}
