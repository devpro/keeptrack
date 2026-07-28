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
}
