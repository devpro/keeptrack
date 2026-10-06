using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Imports a reference-data export (<c>ReferenceDataAdminController.Export</c>) into what the target database holds,
/// matching each document by its <b>provider id</b>, never by its exported <c>_id</c>.
/// <para>
/// A MongoDB <c>_id</c> is local to the database that minted it.
/// Upserting by it would land a work the target already resolved (TMDB 1396) as a second document,
/// which the unique indexes on <c>external_ids.*</c> reject, failing the import partway.
/// A provider id is the same fact everywhere, and the key <c>Resolve&lt;X&gt;Async</c> deduplicates on.
/// Matching on it keeps the target's <c>_id</c>, so every tenant's <c>ReferenceId</c> and every <see cref="CastMemberModel.PersonReferenceId"/> still resolves.
/// </para>
/// <para>
/// One algorithm covers the six collections and every provider, walking whatever keys <see cref="IHasExternalIds.ExternalIds"/> holds, without naming a provider.
/// The <c>_id</c> is the fallback only for a document with no provider id, which keeps re-importing it idempotent.
/// </para>
/// <para>
/// A match <b>merges</b> rather than replaces.
/// An export is a snapshot of one environment, and the target may know more: aliases its own tenants confirmed,
/// and ratings from a provider the exporter never called (an IMDb value costs a metered OMDb call).
/// Accumulated values are unioned, and a value the import lacks leaves the target's, never overwriting with nothing.
/// </para>
/// </summary>
public static class ReferenceDataImportService
{
    /// <param name="onCollectionStarted">
    /// Called as each collection starts, so the caller reports progress.
    /// An import runs as a background job, since a full export holds tens of thousands of documents.
    /// </param>
    /// <param name="cancellationToken">
    /// Checked per document.
    /// A cancelled import stays partly applied, which is safe because it is idempotent: re-running the zip matches what landed by provider id and updates it in place.
    /// </param>
    public static async Task<ReferenceDataImportSummary> ImportAsync(
        ReferenceDataImportPayload payload,
        ReferenceRepositorySet repositories,
        Func<ReferenceDataImportCollection, Task> onCollectionStarted,
        CancellationToken cancellationToken)
    {
        var summary = new ReferenceDataImportSummary();

        // People first: the other collections cite them by id, so a person the target holds under another _id is mapped before any document naming them is written.
        // Otherwise an imported cast row would point at an id that does not exist.
        await onCollectionStarted(ReferenceDataImportCollection.People);
        var personIds = await ImportCollectionAsync(
            payload.People, repositories.People.FindAllAsync, repositories.People.UpsertAsync,
            MergePerson, summary, summary.People, cancellationToken);

        await onCollectionStarted(ReferenceDataImportCollection.TvShows);
        await ImportCollectionAsync(
            payload.TvShows, repositories.TvShows.FindAllAsync, repositories.TvShows.UpsertAsync,
            MergeTvShow, summary, summary.TvShows, cancellationToken, show => RemapCast(show.Cast, personIds),
            show => (show.Title, show.Year), ReferenceDataImportCollection.TvShows);

        await onCollectionStarted(ReferenceDataImportCollection.Movies);
        await ImportCollectionAsync(
            payload.Movies, repositories.Movies.FindAllAsync, repositories.Movies.UpsertAsync,
            MergeMovie, summary, summary.Movies, cancellationToken, movie => RemapCast(movie.Cast, personIds),
            movie => (movie.Title, movie.Year), ReferenceDataImportCollection.Movies);

        await onCollectionStarted(ReferenceDataImportCollection.Books);
        await ImportCollectionAsync(
            payload.Books, repositories.Books.FindAllAsync, repositories.Books.UpsertAsync,
            MergeBook, summary, summary.Books, cancellationToken, book => book.AuthorReferenceId = Remap(book.AuthorReferenceId, personIds),
            book => (book.Title, book.Year), ReferenceDataImportCollection.Books);

        await onCollectionStarted(ReferenceDataImportCollection.VideoGames);
        await ImportCollectionAsync(
            payload.VideoGames, repositories.VideoGames.FindAllAsync, repositories.VideoGames.UpsertAsync,
            MergeVideoGame, summary, summary.VideoGames, cancellationToken,
            identityOf: game => (game.Title, game.Year), collection: ReferenceDataImportCollection.VideoGames);

        await onCollectionStarted(ReferenceDataImportCollection.Albums);
        await ImportCollectionAsync(
            payload.Albums, repositories.Albums.FindAllAsync, repositories.Albums.UpsertAsync,
            MergeAlbum, summary, summary.Albums, cancellationToken, album => album.ArtistReferenceId = Remap(album.ArtistReferenceId, personIds),
            album => (album.Title, album.Year), ReferenceDataImportCollection.Albums);

        return summary;
    }

    /// <summary>
    /// The import algorithm, run once per collection.
    /// The repositories share no base interface, so the two operations it needs are passed as delegates.
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
        Action<T>? remapPersonIds = null,
        Func<T, (string Title, int? Year)>? identityOf = null,
        ReferenceDataImportCollection collection = default)
        where T : class, IHasExternalIds
    {
        var idMap = new Dictionary<string, string>(StringComparer.Ordinal);
        if (imported.Count == 0) return idMap;

        // one read of the whole collection rather than a lookup per document, the volume the export reads anyway
        var existing = await findAllAsync();
        var byExternalId = new Dictionary<string, T>(StringComparer.Ordinal);
        var byId = new Dictionary<string, T>(StringComparer.Ordinal);
        var knownTitles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var document in existing)
        {
            Index(document, byExternalId, byId);
            if (identityOf is not null) knownTitles.Add(TitleKey(identityOf(document)));
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
            if (match is not null)
            {
                counts.Updated++;
            }
            else
            {
                counts.Created++;
                // a new document naming a work the target already knew means the two use different provider ids
                // and could not match (see ReferenceDataImportSummary.PossibleDuplicates)
                if (identityOf is not null)
                {
                    var (title, year) = identityOf(saved);
                    if (knownTitles.Contains(TitleKey((title, year))))
                    {
                        summary.PossibleDuplicates.Add($"{collection}:{title}{(year is null ? "" : $" ({year})")}");
                    }
                }
            }

            if (!string.IsNullOrEmpty(exportedId) && !string.IsNullOrEmpty(saved.Id)) idMap[exportedId] = saved.Id;
            // kept current, so two documents of one archive cannot both claim an id
            Index(saved, byExternalId, byId);
            if (identityOf is not null) knownTitles.Add(TitleKey(identityOf(saved)));
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

        if (!string.IsNullOrEmpty(document.Id)) byId[document.Id] = document;
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
    /// Removes any provider id another target document already holds.
    /// The write would otherwise hit that key's unique index and fail the import, with everything before the failure already written, since an import is not a transaction.
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

    /// <summary>
    /// The "same work" key for reporting duplicates only, never for matching, which is by provider id.
    /// Loose normalization notices a work two catalogues spell differently ("Mass Effect: Legendary Edition" and "Mass Effect Legendary Edition"),
    /// and the year keeps a remake apart from its original.
    /// </summary>
    private static string TitleKey((string Title, int? Year) identity) =>
        $"{TitleNormalizer.NormalizeLoose(identity.Title)}|{identity.Year}";

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
    /// Union, the import winning on a shared key.
    /// A target that adopted a second provider (an IGDB id on a RAWG-linked game) keeps it, or the next sync would adopt it again.
    /// </summary>
    private static void MergeExternalIds(IHasExternalIds existing, IHasExternalIds imported)
    {
        foreach (var (provider, externalId) in existing.ExternalIds)
        {
            imported.ExternalIds.TryAdd(provider, externalId);
        }
    }

    /// <summary>
    /// Union, since an alias is a fact someone confirmed, and the target's were confirmed by its own tenants.
    /// Same rule and equality as enrichment's <c>MergeMatchedAliases</c>.
    /// </summary>
    private static void MergeAliases(List<ReferenceMatchModel> existing, List<ReferenceMatchModel> imported)
    {
        foreach (var alias in existing.Where(alias => !imported.Any(m => m.Matches(alias.Title, alias.Year, alias.Creator, alias.Isbn))))
        {
            imported.Add(alias);
        }
    }

    /// <summary>
    /// The import wins per source, but a source only the target has is kept.
    /// An "imdb" value the exporter had no key to fetch is not discarded by an import that does not mention it.
    /// </summary>
    private static void MergeRatings(Dictionary<string, ReferenceRatingModel> existing, Dictionary<string, ReferenceRatingModel> imported)
    {
        foreach (var (source, rating) in existing)
        {
            imported.TryAdd(source, rating);
        }
    }

    /// <summary>
    /// The later attempt per source wins, since an older stamp in an import must never move the re-attempt window backwards.
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
