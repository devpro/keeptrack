using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// How a shared category is presented and whether it can be copied, decided in one place.
/// Media is a read-only list copyable into the recipient's collection.
/// Collections (collectibles, gear) are a read-only list with no shared reference to copy.
/// Personal data (cars, houses, health) is a read-only detail view, never copyable.
/// The copy endpoint and the owner UI's grouping both derive from it, so they never drift apart.
/// </summary>
public static class ShareCategoryClassifier
{
    public static ShareKind KindOf(ShareCategory category) => category switch
    {
        ShareCategory.Cars or ShareCategory.Houses or ShareCategory.Health => ShareKind.Personal,
        ShareCategory.Collectibles or ShareCategory.Gears => ShareKind.Collection,
        _ => ShareKind.Media
    };

    /// <summary>Only reference-linked media can be copied, never collections or personal data.</summary>
    public static bool IsCopyable(ShareCategory category) => KindOf(category) == ShareKind.Media;
}
