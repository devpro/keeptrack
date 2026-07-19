using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// User-triggered "check for reference match" for books - see
    /// <see cref="TryLinkExistingTvShowReferenceAsync"/> for the full rationale (this is the same local-only,
    /// no-HTTP-call lookup, just against <c>book_reference</c>). A successful match also sets
    /// <see cref="BookModel.Year"/>, <see cref="BookModel.Author"/>, <see cref="BookModel.Genre"/>,
    /// <see cref="BookModel.Language"/> and <see cref="BookModel.Isbn"/> to the reference's canonical values -
    /// the author's name is joined from <see cref="PersonReferenceModel"/> via
    /// <see cref="BookReferenceModel.AuthorReferenceId"/>, and Genre from <see cref="BookReferenceModel.Genres"/>
    /// (joined into the same single free-text field the tenant can otherwise edit by hand).
    /// </summary>
    public async Task<BookModel> TryLinkExistingBookReferenceAsync(BookModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        var reference = await bookReferenceRepository.FindByTitleYearAsync(model.Title, model.Year, model.Author)
                        ?? await bookReferenceRepository.FindByTitleAsync(model.Title, model.Author);

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;
        var authorName = await ResolvePersonNameAsync(reference.AuthorReferenceId);
        var genre = JoinGenres(reference.Genres);

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        if (!string.IsNullOrEmpty(authorName)) model.Author = authorName;
        if (genre is not null) model.Genre = genre;
        if (reference.Language is not null) model.Language = reference.Language;
        if (reference.Isbn is not null) model.Isbn = reference.Isbn;
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await bookRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, authorName, genre, reference.Language, reference.Isbn);

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for books - see <see cref="TryAutoResolveTvShowAsync"/>. Always searches
    /// the deployment's *default* provider (<see cref="BookReferenceClientRegistry.Resolve"/> with a null
    /// key) - this is the unattended background path, so there's no admin picking a provider here. Passing
    /// <paramref name="author"/> narrows the search considerably - without it, a common title easily
    /// returns more than one candidate and the match is correctly left for the admin queue.
    /// <paramref name="isbn"/> is always null on this path today (the Add form doesn't collect it, only the
    /// detail page does), but threaded through anyway so this stays the single place that decides how a
    /// search is issued.
    /// </summary>
    public async Task TryAutoResolveBookAsync(string title, int? year, string? author = null, string? isbn = null)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        var client = bookReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchBooksAsync(title, year, author, isbn);
        if (candidates.Count != 1) return;
        await ResolveBookAsync(title, year, candidates[0].ExternalId, client.ProviderKey, isbn);
    }

    /// <summary>
    /// Resolves a title+year to a specific book provider id, upserts the reference document, and
    /// propagates the link - see <see cref="ResolveTvShowAsync"/>. <paramref name="providerKey"/> is which
    /// registered <see cref="IBookReferenceClient"/> <paramref name="externalId"/> came from - required from
    /// the admin's manual link action (an id is meaningless without knowing which provider issued it once
    /// more than one is registered), defaults to the deployment default for the automatic path above.
    /// <paramref name="isbn"/> is the ISBN that was actually supplied as search input (if any) - it only
    /// ever feeds the *tenant-search* alias entry (what the caller actually searched with), never the
    /// canonical one (which always uses whatever the provider itself reports, <see cref="BookDetails.Isbn"/>,
    /// regardless of what was searched for) - see <see cref="MergeMatchedAliases"/>.
    /// </summary>
    public async Task<BookReferenceModel> ResolveBookAsync(string title, int? year, string externalId, string? providerKey = null, string? isbn = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var client = bookReferenceClientRegistry.Resolve(providerKey);
        var details = await client.GetBookDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Book {externalId} could not be fetched from {client.ProviderKey}.");

        var existing = await bookReferenceRepository.FindByExternalIdAsync(client.ProviderKey, externalId)
                       ?? (details.Author is not null ? await bookReferenceRepository.FindByTitleYearAsync(title, year, details.Author) : null)
                       ?? (details.Author is not null ? await bookReferenceRepository.FindByTitleAsync(title, details.Author) : null);
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds[client.ProviderKey] = externalId;

        var authorReferenceId = !string.IsNullOrEmpty(details.AuthorExternalId)
            ? await ResolvePersonReferenceIdAsync(client.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null)
            : existing?.AuthorReferenceId;

        var model = new BookReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            AuthorReferenceId = authorReferenceId,
            ExternalIds = externalIds,
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases,
                (details.Title, details.Year ?? year, details.Author, details.Isbn),
                (title, year, details.Author, isbn)),
            Genres = details.Genres,
            ImageUrl = details.ImageUrl,
            Language = details.Language ?? existing?.Language,
            Isbn = details.Isbn ?? existing?.Isbn,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await bookReferenceRepository.UpsertAsync(model);
        await bookRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, details.Author, JoinGenres(details.Genres), details.Language, details.Isbn);
        return saved;
    }

    /// <summary>
    /// Re-fetches a book reference from whichever registered provider it was actually linked through,
    /// always doing a full re-fetch when called (unlike TMDB, none of the book providers currently
    /// supported expose a per-id "has this changed" endpoint, so there's no cheap pre-check to skip it) -
    /// see <see cref="RefreshTvShowReferenceAsync"/> for the shared staleness-cutoff mechanism this is
    /// invoked from. Looks up <see cref="BookReferenceModel.ExternalIds"/> against every *currently
    /// registered* provider, not just the deployment default - a reference linked via a non-default
    /// provider must keep refreshing even if the default later changes (this used to only ever check the
    /// single configured client's key, so a reference linked through any other provider silently stopped
    /// refreshing forever). A no-op (returns unchanged) when no registered provider's id is present, or the
    /// provider no longer has details for it.
    /// </summary>
    public async Task<(BookReferenceModel Model, bool DataChanged)> RefreshBookReferenceAsync(BookReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var client = bookReferenceClientRegistry.All.FirstOrDefault(c => reference.ExternalIds.ContainsKey(c.ProviderKey));
        if (client is null) return (reference, false);

        var externalId = reference.ExternalIds[client.ProviderKey];
        var details = await client.GetBookDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        if (!string.IsNullOrEmpty(details.AuthorExternalId))
        {
            reference.AuthorReferenceId = await ResolvePersonReferenceIdAsync(client.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null);
        }
        reference.Genres = details.Genres;
        reference.ImageUrl = details.ImageUrl ?? reference.ImageUrl;
        reference.Language = details.Language ?? reference.Language;
        reference.Isbn = details.Isbn ?? reference.Isbn;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, details.Author, details.Isbn));
        reference.LastEnrichedAt = DateTime.UtcNow;

        return (await bookReferenceRepository.UpsertAsync(reference), true);
    }
}
