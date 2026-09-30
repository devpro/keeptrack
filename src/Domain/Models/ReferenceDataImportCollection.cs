namespace Keeptrack.Domain.Models;

/// <summary>
/// Which of the six reference collections an import is currently writing, reported as each one starts so a
/// caller can show real progress. A full export is tens of thousands of documents (people alone routinely
/// outnumber every other collection put together), so "importing..." with no breakdown says nothing useful.
/// <para>
/// Deliberately not the same enum as the client-facing <c>ReferenceDataImportStage</c>: Domain can't reference
/// <c>WebApi.Contracts</c>, and the two genuinely describe different things - this names a collection, that one
/// names a job stage (including the parse/complete/fail states only the web layer knows about).
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
