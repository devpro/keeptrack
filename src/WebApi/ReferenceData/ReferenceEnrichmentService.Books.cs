using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// User-triggered "check for reference match" for books - see
    /// <see cref="TryLinkExistingTvShowReferenceAsync"/> for the full rationale (this is the same local-only,
    /// no-HTTP-call lookup, just against <c>book_reference</c>). A successful match also sets
    /// <see cref="BookModel.Year"/>, <see cref="BookModel.Author"/> and <see cref="BookModel.Genre"/> to the
    /// reference's canonical values - the author's name is joined from <see cref="PersonReferenceModel"/> via
    /// <see cref="BookReferenceModel.AuthorReferenceId"/>, and Genre from <see cref="BookReferenceModel.Genres"/>
    /// (joined into the same single free-text field the tenant can otherwise edit by hand).
    /// </summary>
    public async Task<BookModel> TryLinkExistingBookReferenceAsync(BookModel model)
    {
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
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await bookRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, authorName, genre);

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for books - see <see cref="TryAutoResolveTvShowAsync"/>. Passing
    /// <paramref name="author"/> narrows the configured book provider's search considerably - without it,
    /// a common title easily returns more than one candidate and the match is correctly left for the
    /// admin queue.
    /// </summary>
    public async Task TryAutoResolveBookAsync(string title, int? year, string? author = null)
    {
        var candidates = await bookReferenceClient.SearchBooksAsync(title, year, author);
        if (candidates.Count != 1) return;
        await ResolveBookAsync(title, year, candidates[0].ExternalId);
    }

    /// <summary>
    /// Resolves a title+year to a specific book provider id, upserts the reference document, and
    /// propagates the link - see <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<BookReferenceModel> ResolveBookAsync(string title, int? year, string externalId)
    {
        var details = await bookReferenceClient.GetBookDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Book {externalId} could not be fetched from {bookReferenceClient.ProviderKey}.");

        var existing = await bookReferenceRepository.FindByExternalIdAsync(bookReferenceClient.ProviderKey, externalId)
                       ?? (details.Author is not null ? await bookReferenceRepository.FindByTitleYearAsync(title, year, details.Author) : null)
                       ?? (details.Author is not null ? await bookReferenceRepository.FindByTitleAsync(title, details.Author) : null);
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds[bookReferenceClient.ProviderKey] = externalId;

        var authorReferenceId = !string.IsNullOrEmpty(details.AuthorExternalId)
            ? await ResolvePersonReferenceIdAsync(bookReferenceClient.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null)
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
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, details.Author), (title, year, details.Author)),
            Genres = details.Genres,
            ImageUrl = details.ImageUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await bookReferenceRepository.UpsertAsync(model);
        await bookRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, details.Author, JoinGenres(details.Genres));
        return saved;
    }

    /// <summary>
    /// Re-fetches a book reference from the configured book provider, always doing a full re-fetch when
    /// called (unlike TMDB, none of the book providers currently supported expose a per-id "has this
    /// changed" endpoint, so there's no cheap pre-check to skip it) - see
    /// <see cref="RefreshTvShowReferenceAsync"/> for the shared staleness-cutoff mechanism this is invoked
    /// from. A no-op (returns unchanged) for a reference with no id from the currently configured provider,
    /// or that the provider no longer has details for.
    /// </summary>
    public async Task<(BookReferenceModel Model, bool DataChanged)> RefreshBookReferenceAsync(BookReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var externalId = reference.ExternalIds.GetValueOrDefault(bookReferenceClient.ProviderKey);
        if (string.IsNullOrEmpty(externalId)) return (reference, false);

        var details = await bookReferenceClient.GetBookDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        if (!string.IsNullOrEmpty(details.AuthorExternalId))
        {
            reference.AuthorReferenceId = await ResolvePersonReferenceIdAsync(bookReferenceClient.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null);
        }
        reference.Genres = details.Genres;
        reference.ImageUrl = details.ImageUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, details.Author));
        reference.LastEnrichedAt = DateTime.UtcNow;

        return (await bookReferenceRepository.UpsertAsync(reference), true);
    }
}
