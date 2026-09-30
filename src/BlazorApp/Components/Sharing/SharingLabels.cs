using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Sharing;

/// <summary>
/// Human-readable labels for the sharing categories, in one place so the owner and recipient pages never
/// drift on how a category is named.
/// </summary>
public static class SharingLabels
{
    public static string Category(ShareCategory category) => category switch
    {
        ShareCategory.TvShows => "TV shows",
        ShareCategory.VideoGames => "Video games",
        ShareCategory.Gears => "Gear",
        _ => category.ToString()
    };

    // The categories' canonical display order, matching the left nav menu (NavMenu.razor), so tabs and
    // summaries read the same way everywhere regardless of the order the owner happened to click them when
    // creating the share (which is what a raw stored order reflects). Any category missing here sorts last.
    private static readonly ShareCategory[] s_displayOrder =
    [
        ShareCategory.Movies,
        ShareCategory.TvShows,
        ShareCategory.Books,
        ShareCategory.Albums,
        ShareCategory.VideoGames,
        ShareCategory.Cars,
        ShareCategory.Houses,
        ShareCategory.Health,
        ShareCategory.Collectibles,
        ShareCategory.Gears
    ];

    /// <summary>The given categories in the left-menu display order, not their stored (click) order.</summary>
    public static IEnumerable<ShareCategory> Ordered(IEnumerable<ShareCategory> categories)
    {
        var order = s_displayOrder;
        return categories.OrderBy(c =>
        {
            var index = Array.IndexOf(order, c);
            return index < 0 ? int.MaxValue : index;
        });
    }
}
