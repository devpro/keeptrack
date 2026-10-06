namespace Keeptrack.Domain.Models;

/// <summary>
/// Which of the six reference collections an import is writing, reported as each one starts so a caller shows real progress.
/// A full export is tens of thousands of documents, people outnumbering every other collection together, so a bare "importing" says nothing useful.
/// <para>
/// It is not the client-facing <c>ReferenceDataImportStage</c>: Domain cannot reference <c>WebApi.Contracts</c>, and the two describe different things.
/// This names a collection, that one a job stage, including the parse, complete and fail states only the web layer knows.
/// </para>
/// </summary>
public enum ReferenceDataImportCollection
{
    People,
    TvShows,
    Movies,
    Books,
    VideoGames,
    Albums
}
