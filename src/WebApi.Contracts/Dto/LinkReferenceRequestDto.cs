namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// An admin's manual choice: link every tenant's (Title, Year) match to this external provider id
/// (TMDB, Open Library, RAWG or Discogs, depending on <see cref="Type"/>).
/// </summary>
public class LinkReferenceRequestDto
{
    public required ReferenceItemType Type { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public required string ExternalId { get; set; }
}
