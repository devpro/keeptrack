using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Book metadata from a book provider (Google Books, Open Library or BnF), shared by every tenant.
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class BookReferenceModel : IHasExternalIds
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// The author's shared <see cref="PersonReferenceModel"/>, deduplicated by the linking provider's author id like TV and movie cast.
    /// Null when the provider reported no author id to deduplicate by.
    /// </summary>
    public string? AuthorReferenceId { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every combination confirmed to mean this book (see <see cref="TvShowReferenceModel.MatchedAliases"/>).
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    /// <summary>
    /// Aggregate ratings keyed by provider ("googlebooks", "openlibrary"; BnF reports none), see <see cref="ReferenceRatingModel"/>.
    /// </summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    public string? ImageUrl { get; set; }

    /// <summary>
    /// The book's language, when the linking provider reports one.
    /// BnF's Dublin Core always does, and Open Library's client never fills it (see <see cref="BookDetails.Language"/>).
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// The book's ISBN, when the linking provider reports one.
    /// Google Books and BnF can, and Open Library's client never fills it (see <see cref="BookDetails.Isbn"/>).
    /// </summary>
    public string? Isbn { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
