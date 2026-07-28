using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// The single place the "is this category ordinary media or personal/sensitive" rule lives. Media is
/// viewable and copyable into the recipient's own collection; personal data (cars, houses, health) is
/// view-only and never copyable. Both the copy endpoint's gate and the owner UI's grouping derive from
/// this, so the rule can never drift between them.
/// </summary>
public static class ShareCategoryClassifier
{
    public static ShareKind KindOf(ShareCategory category) => category switch
    {
        ShareCategory.Cars or ShareCategory.Houses or ShareCategory.Health => ShareKind.Personal,
        _ => ShareKind.Media
    };

    /// <summary>Media categories can be copied; personal ones never can.</summary>
    public static bool IsCopyable(ShareCategory category) => KindOf(category) == ShareKind.Media;
}
