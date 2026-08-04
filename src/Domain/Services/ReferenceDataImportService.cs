using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Re-imports a reference-data export (see <c>ReferenceDataAdminController.Export</c>) into whatever the target
/// database already holds, matching each document by its <b>provider id</b> - never by the <c>_id</c> it was
/// exported with.
/// <para>
/// That distinction is the whole feature. A Mongo <c>_id</c> is local to the database that minted it, so
/// upserting by it means the same real work (TMDB 1396) lands as a *second* document in any environment that
/// had already resolved it on its own - which the unique partial indexes on <c>external_ids.*</c> reject
/// outright, failing the import partway through. A provider id, by contrast, is the same fact in every
/// environment, and is exactly the key <c>Resolve&lt;X&gt;Async</c> already dedupes on. Matching on it means
/// the target's own <c>_id</c> is preserved, so every tenant's <c>ReferenceId</c> - and every
/// <see cref="CastMemberModel.PersonReferenceId"/> - still resolves after an import.
/// </para>
/// <para>
/// The same algorithm covers all six collections and every provider: matching walks whatever keys a document
/// carries in <see cref="IHasExternalIds.ExternalIds"/>, so a book linked through Google Books, a game that
/// gained an IGDB id on top of its RAWG one, and a person known by a Discogs id all match without the
/// algorithm naming a single provider. An <c>_id</c> match is kept only as the fallback for a document with no
/// provider id at all (hand-created or pre-dating the field), which is what keeps re-importing idempotent for it.
/// </para>
/// <para>
/// A match <b>merges</b> rather than replaces. An export is a snapshot of one environment, and the target may
/// legitimately know things it doesn't: aliases confirmed by its own tenants' searches, and ratings earned from
/// a provider the exporting environment never called (an IMDb value costs a metered OMDb call - see
/// <c>OmdbCallBudget</c>). Anything accumulated is unioned; anything the import has no value for leaves the
/// target's alone, the same "never overwrite with nothing" rule <c>SetReferenceLinkAsync</c> follows.
/// </para>
/// </summary>
public static class ReferenceDataImportService
{
    /// <param name="onCollectionStarted">
    /// Called as each collection starts, so the caller can report progress. An import is a long-running
    /// background job (a full export runs to tens of thousands of documents), never a blocking request.
    /// </param>
    /// <param name="cancellationToken">
    /// Checked per document. A cancelled import stops partway and stays partly applied, which is safe
    /// precisely because the whole thing is idempotent: re-running the same zip matches what already landed
    /// by provider id and updates it in place a second time.
    /// </param>
    public static async Task<ReferenceDataImportSummary> ImportAsync(
        ReferenceDataImportPayload payload,
        ReferenceRepositorySet repositories,
        Func<ReferenceDataImportCollection, Task> onCollectionStarted,
        CancellationToken cancellationToken)
    {
        var summary = new ReferenceDataImportSummary();

        // People first, and not just for tidiness: the other five collections cite them by id, so a person who
        // already exists in the target under a different _id has to be discovered - and mapped - before any
        // document naming them is written, or every imported cast row would point at an id that isn't there.
        await onCollectionStarted(ReferenceDataImportCollection.People);
        var personIds = await ImportCollectionAsync(
            payload.People, repositories.People.FindAllAsync, repositories.People.UpsertAsync,
            MergePerson, summary, summary.People, cancellationToken);

        await onCollectionStarted(ReferenceDataImportCollection.TvShows);
        await ImportCollectionAsync(
            payload.TvShows, repositories.TvShows.FindAllAsync, repositories.TvShows.UpsertAsync,
            MergeTvShow, summary, summary.TvShows, cancellationToken, show => RemapCast(show.Cast, personIds));

        await onCollectionStarted(ReferenceDataImportCollection.Movies);
        await ImportCollectionAsync(
            payload.Movies, repositories.Movies.FindAllAsync, repositories.Movies.UpsertAsync,
            MergeMovie, summary, summary.Movies, cancellationToken, movie => RemapCast(movie.Cast, personIds));

        await onCollectionStarted(ReferenceDataImportCollection.Books);
        await ImportCollectionAsync(
            payload.Books, repositories.Books.FindAllAsync, repositories.Books.UpsertAsync,
            MergeBook, summary, summary.Books, cancellationToken, book => book.AuthorReferenceId = Remap(book.AuthorReferenceId, personIds));

        await onCollectionStarted(ReferenceDataImportCollection.VideoGames);
        await ImportCollectionAsync(
            payload.VideoGames, repositories.VideoGames.FindAllAsync, repositories.VideoGames.UpsertAsync,
            MergeVideoGame, summary, summary.VideoGames, cancellationToken);

        await onCollectionStarted(ReferenceDataImportCollection.Albums);
        await ImportCollectionAsync(
            payload.Albums, repositories.Albums.FindAllAsync, repositories.Albums.UpsertAsync,
            MergeAlbum, summary, summary.Albums, cancellationToken, album => album.ArtistReferenceId = Remap(album.ArtistReferenceId, personIds));

        return summary;
    }

    /// <summary>
    /// The one import algorithm, run once per collection. The repositories share no common base interface
    /// (each is purpose-built for its owner-less collection), so the two operations it needs are passed as
    /// delegates rather than the whole repository.
    /// </summary>
    /// <returns>Exported <c>_id</c> to the <c>_id</c> the document actually landed under, so documents citing this collection can be remapped.</returns>
    private static async Task<Dictionary<string, string>> ImportCollectionAsync<T>(
        IReadOnlyList<T> imported,
        Func<Task<List<T>>> findAllAsync,
        Func<T, Task<T>> upsertAsync,
        Action<T, T> merge,
        ReferenceDataImportSummary summary,
        ReferenceDataImportCounts counts,
        CancellationToken cancellationToken,
        Action<T>? remapPersonIds = null)
        where T : class, IHasExternalIds
    {
        var idMap = new Dictionary<string, string>(StringComparer.Ordinal);
        if (imported.Count == 0) return idMap;

        // One read of the whole collection rather than a lookup per imported document: this is the same data
        // volume the export itself already reads, and an import walks all of it anyway.
        var existing = await findAllAsync();
        var byExternalId = new Dictionary<string, T>(StringComparer.Ordinal);
        var byId = new Dictionary<string, T>(StringComparer.Ordinal);
        foreach (var document in existing)
        {
            Index(document, byExternalId, byId);
        }

        foreach (var document in imported)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var exportedId = document.Id;
            // before matching/merging, so a kept-from-the-target cast list is never remapped a second time
            remapPersonIds?.Invoke(document);

            var match = FindMatch(document, byExternalId, byId);
            if (match is not null)
            {
                merge(match, document);
                document.Id = match.Id;
            }

            DropConflictingExternalIds(document, byExternalId, summary.SkippedExternalIds);

            var saved = await upsertAsync(document);
            if (match is not null) counts.Updated++;
            else counts.Created++;

            if (!string.IsNullOrEmpty(exportedId) && !string.IsNullOrEmpty(saved.Id)) idMap[exportedId] = saved.Id!;
            // keep the index current, so two documents inside the same archive can't both claim one id
            Index(saved, byExternalId, byId);
        }

        return idMap;
    }

    private static void Index<T>(T document, Dictionary<string, T> byExternalId, Dictionary<string, T> byId)
        where T : class, IHasExternalIds
    {
        foreach (var (provider, externalId) in document.ExternalIds)
        {
            byExternalId[ExternalKey(provider, externalId)] = document;
        }

        if (!string.IsNullOrEmpty(document.Id)) byId[document.Id!] = document;
    }

    private static T? FindMatch<T>(T document, Dictionary<string, T> byExternalId, Dictionary<string, T> byId)
        where T : class, IHasExternalIds
    {
        // ordered so a document carrying several provider ids resolves to the same target document every run
        foreach (var (provider, externalId) in document.ExternalIds.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (byExternalId.TryGetValue(ExternalKey(provider, externalId), out var found)) return found;
        }

        return !string.IsNullOrEmpty(document.Id) && byId.TryGetValue(document.Id!, out var byIdMatch) ? byIdMatch : null;
    }

    /// <summary>
    /// Removes any provider id that a *different* target document already holds. Without this the write hits
    /// the unique partial index on that key and takes the whole import down with it (a zip is not a
    /// transaction - everything before the failure has already been written).
    /// </summary>
    private static void DropConflictingExternalIds<T>(T document, Dictionary<string, T> byExternalId, List<string> skipped)
        where T : class, IHasExternalIds
    {
        foreach (var (provider, externalId) in document.ExternalIds.ToList())
        {
            var key = ExternalKey(provider, externalId);
            if (byExternalId.TryGetValue(key, out var owner) && !ReferenceEquals(owner, document) && owner.Id != document.Id)
            {
                document.ExternalIds.Remove(provider);
                skipped.Add(key);
            }
        }
    }

    private static string ExternalKey(string provider, string externalId) => $"{provider}:{externalId}";

    private static void MergePerson(PersonReferenceModel existing, PersonReferenceModel imported)
    {
        MergeExternalIds(existing, imported);
        imported.Name = Coalesce(imported.Name, existing.Name)!;
        imported.ProfileImageUrl = Coalesce(imported.ProfileImageUrl, existing.ProfileImageUrl);
    }

    private static void MergeTvShow(TvShowReferenceModel existing, TvShowReferenceModel imported)
    {
        MergeExternalIds(existing, imported);
        MergeAliases(existing.MatchedAliases, imported.MatchedAliases);
        MergeRatings(existing.Ratings, imported.Ratings);
        MergeRatingsCheckedAt(existing.RatingsCheckedAt, imported.RatingsCheckedAt);
        imported.Year ??= existing.Year;
        imported.Synopsis = Coalesce(imported.Synopsis, existing.Synopsis);
        imported.ImageUrl = Coalesce(imported.ImageUrl, existing.ImageUrl);
        imported.Episodes = Coalesce(imported.Episodes, existing.Episodes);
        imported.Genres = Coalesce(imported.Genres, existing.Genres);
        imported.Cast = Coalesce(imported.Cast, existing.Cast);
        imported.LastEnrichedAt ??= existing.LastEnrichedAt;
    }

    private static void MergeMovie(MovieReferenceModel existing, MovieReferenceModel imported)
    {
        MergeExternalIds(existing, imported);
        MergeAliases(existing.MatchedAliases, imported.MatchedAliases);
        MergeRatings(existing.Ratings, imported.Ratings);
        MergeRatingsCheckedAt(existing.RatingsCheckedAt, imported.RatingsCheckedAt);
        imported.Year ??= existing.Year;
        imported.Synopsis = Coalesce(imported.Synopsis, existing.Synopsis);
        imported.ImageUrl = Coalesce(imported.ImageUrl, existing.ImageUrl);
        imported.Genres = Coalesce(imported.Genres, existing.Genres);
        imported.Cast = Coalesce(imported.Cast, existing.Cast);
        imported.LastEnrichedAt ??= existing.LastEnrichedAt;
    }

    private static void MergeBook(BookReferenceModel existing, BookReferenceModel imported)
    {
        MergeExternalIds(existing, imported);
        MergeAliases(existing.MatchedAliases, imported.MatchedAliases);
        MergeRatings(existing.Ratings, imported.Ratings);
        imported.Year ??= existing.Year;
        imported.Synopsis = Coalesce(imported.Synopsis, existing.Synopsis);
        imported.ImageUrl = Coalesce(imported.ImageUrl, existing.ImageUrl);
        imported.Language = Coalesce(imported.Language, existing.Language);
        imported.Isbn = Coalesce(imported.Isbn, existing.Isbn);
        imported.AuthorReferenceId = Coalesce(imported.AuthorReferenceId, existing.AuthorReferenceId);
        imported.Genres = Coalesce(imported.Genres, existing.Genres);
        imported.LastEnrichedAt ??= existing.LastEnrichedAt;
    }

    private static void MergeVideoGame(VideoGameReferenceModel existing, VideoGameReferenceModel imported)
    {
        MergeExternalIds(existing, imported);
        MergeAliases(existing.MatchedAliases, imported.MatchedAliases);
        MergeRatings(existing.Ratings, imported.Ratings);
        imported.Year ??= existing.Year;
        imported.Synopsis = Coalesce(imported.Synopsis, existing.Synopsis);
        imported.ImageUrl = Coalesce(imported.ImageUrl, existing.ImageUrl);
        imported.Platforms = Coalesce(imported.Platforms, existing.Platforms);
        imported.Genres = Coalesce(imported.Genres, existing.Genres);
        imported.LastEnrichedAt ??= existing.LastEnrichedAt;
    }

    private static void MergeAlbum(AlbumReferenceModel existing, AlbumReferenceModel imported)
    {
        MergeExternalIds(existing, imported);
        MergeAliases(existing.MatchedAliases, imported.MatchedAliases);
        MergeRatings(existing.Ratings, imported.Ratings);
        imported.Year ??= existing.Year;
        imported.Synopsis = Coalesce(imported.Synopsis, existing.Synopsis);
        imported.ImageUrl = Coalesce(imported.ImageUrl, existing.ImageUrl);
        imported.ArtistReferenceId = Coalesce(imported.ArtistReferenceId, existing.ArtistReferenceId);
        imported.Tracks = Coalesce(imported.Tracks, existing.Tracks);
        imported.Genres = Coalesce(imported.Genres, existing.Genres);
        imported.LastEnrichedAt ??= existing.LastEnrichedAt;
    }

    /// <summary>
    /// Union, import wins on a shared key: a target that adopted a second provider (an IGDB id on a
    /// RAWG-linked game) keeps it, since dropping it would make that reference re-adopt on the next sync.
    /// </summary>
    private static void MergeExternalIds(IHasExternalIds existing, IHasExternalIds imported)
    {
        foreach (var (provider, externalId) in existing.ExternalIds)
        {
            imported.ExternalIds.TryAdd(provider, externalId);
        }
    }

    /// <summary>
    /// Union - an alias is a fact someone confirmed, and the target's were confirmed by its own tenants'
    /// searches. Same rule (and same equality) as enrichment's <c>MergeMatchedAliases</c>.
    /// </summary>
    private static void MergeAliases(List<ReferenceMatchModel> existing, List<ReferenceMatchModel> imported)
    {
        foreach (var alias in existing.Where(alias => !imported.Any(m => m.Matches(alias.Title, alias.Year, alias.Creator, alias.Isbn))))
        {
            imported.Add(alias);
        }
    }

    /// <summary>
    /// Per source, import wins - but a source only the target has is kept. An "imdb" value the exporting
    /// environment never had a key to fetch must not be thrown away by an import that simply doesn't mention it.
    /// </summary>
    private static void MergeRatings(Dictionary<string, ReferenceRatingModel> existing, Dictionary<string, ReferenceRatingModel> imported)
    {
        foreach (var (source, rating) in existing)
        {
            imported.TryAdd(source, rating);
        }
    }

    /// <summary>
    /// The later attempt per source wins: this marker exists to stop a source being re-asked, so an older
    /// stamp arriving in an import must never move the re-attempt window backwards.
    /// </summary>
    private static void MergeRatingsCheckedAt(Dictionary<string, DateTime> existing, Dictionary<string, DateTime> imported)
    {
        foreach (var (source, checkedAt) in existing)
        {
            if (!imported.TryGetValue(source, out var known) || known < checkedAt) imported[source] = checkedAt;
        }
    }

    private static void RemapCast(List<CastMemberModel> cast, Dictionary<string, string> personIds)
    {
        foreach (var member in cast)
        {
            member.PersonReferenceId = Remap(member.PersonReferenceId, personIds) ?? member.PersonReferenceId;
        }
    }

    private static string? Remap(string? personReferenceId, Dictionary<string, string> personIds) =>
        !string.IsNullOrEmpty(personReferenceId) && personIds.TryGetValue(personReferenceId, out var mapped)
            ? mapped
            : personReferenceId;

    private static string? Coalesce(string? imported, string? existing) => string.IsNullOrWhiteSpace(imported) ? existing : imported;

    private static List<T> Coalesce<T>(List<T> imported, List<T> existing) => imported.Count > 0 ? imported : existing;
}
