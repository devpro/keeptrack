using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One Explore suggestion: a top-rated provider title the caller doesn't already track and hasn't dismissed.
/// <see cref="ExternalId"/> (the provider/TMDB id) keys the dismiss action; adding uses <see cref="Title"/>/
/// <see cref="Year"/> to create and auto-resolve a collection item.
/// </summary>
public class ExploreSuggestionDto
{
    /// <summary>The provider's external id (TMDB id) of this title.</summary>
    public required string ExternalId { get; set; }

    /// <summary>Canonical title from the reference provider.</summary>
    public required string Title { get; set; }

    /// <summary>Release/first-air year, when known.</summary>
    public int? Year { get; set; }

    /// <summary>Cover/poster image URL (hotlinked from the provider's CDN), when available.</summary>
    public string? ImageUrl { get; set; }

    /// <summary>Provider synopsis, when available.</summary>
    public string? Synopsis { get; set; }

    /// <summary>Provider genres, when available.</summary>
    public List<string> Genres { get; set; } = [];

    /// <summary>The ranking source's rating value (the value the suggestions were ordered by).</summary>
    public double? Rating { get; set; }

    /// <summary>Scale of <see cref="Rating"/> (10 for TMDB/IMDb, 5 for RAWG, 100 for Metacritic).</summary>
    public double? RatingScale { get; set; }

    /// <summary>
    /// The title's own page on a provider's website, for a card to open in a new tab so the suggestion can be
    /// read up on before it is added or dismissed. It follows the rating the card displays wherever possible -
    /// a movie shown with an IMDb score links to IMDb - and otherwise falls back to the provider the
    /// suggestion was discovered through. Null when neither is known (an entry written before links were
    /// stored, or a provider that reported no page), in which case the card simply isn't a link.
    /// </summary>
    public string? ProviderUrl { get; set; }

    /// <summary>
    /// The name of the website <see cref="ProviderUrl"/> opens ("IMDb", "TMDB", "IGDB"), so the client can
    /// label the link without keeping its own copy of every provider's name. Null exactly when
    /// <see cref="ProviderUrl"/> is.
    /// </summary>
    public string? ProviderName { get; set; }
}
