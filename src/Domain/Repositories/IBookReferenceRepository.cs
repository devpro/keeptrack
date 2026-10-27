using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared book reference collection.
/// See <see cref="ITvShowReferenceRepository"/> for why it does not extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IBookReferenceRepository
{
    Task<BookReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup for list-page cover hydration: one query per page, never one per item.
    /// </summary>
    Task<List<BookReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// <paramref name="author"/> is part of the key, not a search hint:
    /// two different books easily share a generic title and a year, so title and year alone could link an unrelated book.
    /// See <see cref="Domain.Models.ReferenceMatchModel.Creator"/>.
    /// </summary>
    Task<BookReferenceModel?> FindByTitleYearAsync(string title, int? year, string author);

    /// <summary>
    /// The tier ignoring the year (normalized title and author), asked when no alias carries the tenant's year.
    /// That is the ordinary case, since a work is republished years apart, so a year identifies a printing rather than the book.
    /// Ambiguity is refused rather than guessed, since two works can share a title and an author's name, so several matches answer the same as none.
    /// </summary>
    Task<BookReferenceModel?> FindByTitleAsync(string title, string author);

    /// <summary>
    /// The reference confirmed under this ISBN, the strongest key of this domain and the first asked.
    /// An ISBN names one printing outright, so it matches a work recorded under a translated title that no text matching would connect.
    /// It reads the aliases, so it matches the ISBN the provider reported and one a tenant searched with (see <see cref="Domain.Models.ReferenceMatchModel.Isbn"/>).
    /// </summary>
    Task<BookReferenceModel?> FindByIsbnAsync(string isbn);

    /// <summary>
    /// Looks up a reference by provider id (a Google Books volume id, an Open Library work id), the strongest sign of the same book, whatever its title.
    /// </summary>
    Task<BookReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<BookReferenceModel> UpsertAsync(BookReferenceModel model);

    /// <summary>
    /// Every reference document, for the admin export.
    /// An unpaged read is fine, since this shared metadata is bounded and not per tenant.
    /// </summary>
    Task<List<BookReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync refreshes next,
    /// among those untouched since <paramref name="cutoff"/>: never enriched first, then least recently enriched.
    /// The ordering makes the cap safe, since what a pass does not reach leads the next one rather than the same head of the collection being walked forever.
    /// </summary>
    Task<List<BookReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document, for the admin unlink, which deletes the shared document rather than detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
