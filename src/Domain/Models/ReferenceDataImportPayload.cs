using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One reference-data export's six collections, read out of the uploaded zip and handed to
/// <see cref="Services.ReferenceDataImportService"/>. A collection missing from the archive is simply empty -
/// an export taken before a collection existed still imports.
/// </summary>
public class ReferenceDataImportPayload
{
    public List<TvShowReferenceModel> TvShows { get; init; } = [];

    public List<MovieReferenceModel> Movies { get; init; } = [];

    public List<PersonReferenceModel> People { get; init; } = [];

    public List<BookReferenceModel> Books { get; init; } = [];

    public List<VideoGameReferenceModel> VideoGames { get; init; } = [];

    public List<AlbumReferenceModel> Albums { get; init; } = [];
}
