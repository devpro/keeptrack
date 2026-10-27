using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One Explore suggestion: a top-rated title the caller does not track and has not dismissed.
/// <see cref="ExternalId"/> keys the dismiss and add actions, and adding creates the item from <see cref="Title"/> and <see cref="Year"/>.
/// </summary>
public class ExploreSuggestionDto
{
    /// <summary>The discovery provider's id of this title (a TMDB or IGDB id).</summary>
    public required string ExternalId { get; set; }

    /// <summary>Canonical title from the reference provider.</summary>
    public required string Title { get; set; }

    /// <summary>Release or first-air year, when known.</summary>
    public int? Year { get; set; }

    /// <summary>Cover image URL, hotlinked from the provider's CDN, when available.</summary>
    public string? ImageUrl { get; set; }

    /// <summary>Provider synopsis, when available.</summary>
    public string? Synopsis { get; set; }

    /// <summary>Provider genres, when available.</summary>
    public List<string> Genres { get; set; } = [];

    /// <summary>The displayed rating, usually the one the suggestions were ordered by.</summary>
    public double? Rating { get; set; }

    /// <summary>Scale of <see cref="Rating"/> (10 for TMDB and IMDb, 100 for IGDB).</summary>
    public double? RatingScale { get; set; }

    /// <summary>
    /// The title's page on a provider's website, which the card opens in a new tab so the suggestion can be read about before adding or dismissing it.
    /// It follows the displayed rating where possible, so a movie shown with an IMDb score links to IMDb, and otherwise the discovery provider.
    /// Null when neither page is known, and the card is then not a link.
    /// </summary>
    public string? ProviderUrl { get; set; }

    /// <summary>
    /// The name of the website <see cref="ProviderUrl"/> opens ("IMDb", "TMDB", "IGDB"), so the client labels the link without its own list of providers.
    /// Null exactly when <see cref="ProviderUrl"/> is.
    /// </summary>
    public string? ProviderName { get; set; }
}
