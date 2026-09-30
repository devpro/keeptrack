using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less book reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IBookReferenceRepository
{
    Task<BookReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup backing list-page image hydration - one query per page instead of one per item.
    /// </summary>
    Task<List<BookReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// <paramref name="author"/> is required (not optional) as part of the match key, not just a search
    /// hint: two different tenants' different books can easily share the same (title, year) - a generic
    /// title re-published the same year is common - so title+year alone risks silently linking a tenant
    /// to another tenant's unrelated book. See <see cref="Domain.Models.ReferenceMatchModel.Creator"/>.
    /// </summary>
    Task<BookReferenceModel?> FindByTitleYearAsync(string title, int? year, string author);

    /// <summary>
    /// The year-agnostic tier (normalized title + author), asked whenever no alias carries the tenant's own year - which is the ordinary case rather than an edge one: the same work is republished as revisions years apart, so the year identifies a printing and not the book.
    /// Ambiguity is refused rather than guessed at (two works can genuinely share a title and an author's name), so several matches answer the same as none.
    /// </summary>
    Task<BookReferenceModel?> FindByTitleAsync(string title, string author);

    /// <summary>
    /// The reference confirmed under this ISBN - the strongest key this domain has, and the first one asked: an ISBN names one printing outright, so it matches a tenant who recorded the work under a translated title no amount of text matching would connect.
    /// It reads the aliases, so it matches both the ISBN the provider reported for the work (carried by the canonical alias) and one a tenant genuinely searched with - see <see cref="Domain.Models.ReferenceMatchModel.Isbn"/>.
    /// </summary>
    Task<BookReferenceModel?> FindByIsbnAsync(string isbn);

    /// <summary>
    /// Looks up a reference document by external provider id (e.g. its Open Library work id) - the
    /// strongest possible "is this genuinely the same book" signal, unaffected by title text ever diverging.
    /// </summary>
    Task<BookReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<BookReferenceModel> UpsertAsync(BookReferenceModel model);

    /// <summary>
    /// Every reference document, for admin export. Bounded, shared metadata (not per-tenant), so a
    /// full unpaged read is fine.
    /// </summary>
    Task<List<BookReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync should refresh next: never enriched
    /// first, then least-recently enriched, and only those untouched since <paramref name="cutoff"/>.
    /// The ordering is what makes the cap safe - a pass takes the oldest, so what it doesn't reach is first
    /// in line next time, instead of the head of the collection being re-walked forever.
    /// </summary>
    Task<List<BookReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document - backs the admin "unlink" action, which deletes the
    /// shared document outright rather than merely detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
