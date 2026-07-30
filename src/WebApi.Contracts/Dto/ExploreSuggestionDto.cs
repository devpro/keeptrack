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
}
