using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Every lookup against <c>matched_aliases</c>, written once for all five reference collections - they differ only in which of the alias's fields their domain's identity is made of, so each repository picks a method here rather than rebuilding the same <c>ElemMatch</c>.
/// The same consolidation as <see cref="ReferenceRatingQueries"/>, over <see cref="IHasMatchedAliases"/>.
/// <para>
/// Every condition goes inside one <c>ElemMatch</c> on purpose: the fields must hold on the <b>same</b> array element, or a title from one alias and a year from another would satisfy a query neither alias ever confirmed.
/// It is also what keeps these queries indexed - see the compound <c>matched_aliases.*</c> indexes in <c>scripts/mongodb-create-index.js</c>, one per domain shaped like the lookup that domain actually issues.
/// </para>
/// </summary>
internal static class ReferenceAliasQueries
{
    /// <summary>
    /// The reference confirmed under this exact (title, year) - films, shows and games, whose identity is those two fields together.
    /// </summary>
    /// <remarks>
    /// <c>FirstOrDefault</c>, not <see cref="FindSingleMatchAsync{TEntity}"/>: two documents sharing a title <i>and</i> a year are a duplicate to be merged, not an ambiguity to refuse - they are the same work, so either answers the question, and refusing would break linking until an admin merged them.
    /// </remarks>
    internal static Task<TEntity?> FindByTitleYearAsync<TEntity>(IMongoCollection<TEntity> collection, string title, int? year)
        where TEntity : class, IHasMatchedAliases =>
        FindFirstAsync(collection, Alias<TEntity>(
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, TitleNormalizer.Normalize(title))
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year)));

    /// <summary>
    /// The reference confirmed under this (title, year, creator) - books, whose printings the year tells apart but whose title a creator is still needed to disambiguate.
    /// </summary>
    internal static Task<TEntity?> FindByTitleYearCreatorAsync<TEntity>(IMongoCollection<TEntity> collection, string title, int? year, string creator)
        where TEntity : class, IHasMatchedAliases =>
        FindFirstAsync(collection, Alias<TEntity>(
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, TitleNormalizer.Normalize(title))
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, TitleNormalizer.Normalize(creator))));

    /// <summary>
    /// The reference confirmed under this (title, creator), whatever year either side records - an album's whole identity, and a book's fallback when the tenant's year names an edition nobody has confirmed yet (which is the ordinary case: one work is reprinted under as many years as it has printings).
    /// </summary>
    /// <param name="refuseAmbiguous">
    /// Whether several matches mean "leave it unresolved" (books: two works can genuinely share a title and an author's name, and picking one would be a guess) or "either will do" (albums: a title plus an artist is the identity, so two matching documents are a duplicate to merge, exactly like <see cref="FindByTitleYearAsync{TEntity}"/>'s pair).
    /// </param>
    /// <param name="collection">
    /// </param>
    /// <param name="title">
    /// </param>
    /// <param name="creator">
    /// </param>
    internal static Task<TEntity?> FindByTitleCreatorAsync<TEntity>(IMongoCollection<TEntity> collection, string title, string creator, bool refuseAmbiguous)
        where TEntity : class, IHasMatchedAliases
    {
        var filter = Alias<TEntity>(
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, TitleNormalizer.Normalize(title))
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, TitleNormalizer.Normalize(creator)));
        return refuseAmbiguous ? FindSingleMatchAsync(collection, filter) : FindFirstAsync(collection, filter);
    }

    /// <summary>
    /// The reference confirmed under this ISBN - books only, and the strongest key the domain has: an ISBN names one printing outright, so it is asked before any title text is and matches a tenant who recorded the work under a translated title nothing else would connect.
    /// </summary>
    internal static Task<TEntity?> FindByIsbnAsync<TEntity>(IMongoCollection<TEntity> collection, string isbn)
        where TEntity : class, IHasMatchedAliases =>
        FindFirstAsync(collection, Alias<TEntity>(Builders<ReferenceMatch>.Filter.Eq(m => m.Isbn, isbn.Trim())));

    /// <summary>
    /// The <b>single</b> reference carrying this title, or null when none does <b>or when several do</b> - the yearless fallback for films, shows and games, reached only when the caller has no year to identify the work with (see <c>ReferenceEnrichmentService.TryLinkExisting*ReferenceAsync</c>).
    /// </summary>
    internal static Task<TEntity?> FindByTitleAsync<TEntity>(IMongoCollection<TEntity> collection, string title)
        where TEntity : class, IHasMatchedAliases =>
        FindSingleMatchAsync(collection, Alias<TEntity>(Builders<ReferenceMatch>.Filter.Eq(m => m.Title, TitleNormalizer.Normalize(title))));

    private static FilterDefinition<TEntity> Alias<TEntity>(FilterDefinition<ReferenceMatch> conditions)
        where TEntity : class, IHasMatchedAliases =>
        Builders<TEntity>.Filter.ElemMatch(x => x.MatchedAliases, conditions);

    private static async Task<TEntity?> FindFirstAsync<TEntity>(IMongoCollection<TEntity> collection, FilterDefinition<TEntity> filter)
        where TEntity : class =>
        await collection.Find(filter).FirstOrDefaultAsync();

    /// <summary>
    /// The single document matching <paramref name="filter"/>, or null when none matches <b>or when several do</b>.
    /// <para>
    /// It used to be a plain <c>FirstOrDefaultAsync</c> over an unsorted, unbounded match, so where several reference documents share a title it returned whichever one the database happened to hand back first - a guess dressed up as an answer, and one stable enough to look deliberate.
    /// Reported from the running app: a yearless "Resident Evil 2" silently adopted the 2019 remake's reference, and did it again after the link was deleted.
    /// IGDB holds eight games named exactly "Resident Evil 2".
    /// </para>
    /// <para>
    /// <b>"Ambiguous" and "no match" are the same answer to a caller that must not guess</b>, so both are null - which is why this needed no new call site handling: every caller already treats null as "leave it unresolved".
    /// A single match is untouched, and that is the ordinary case these fallbacks exist for.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Reads two documents, never a count: "is there more than one" is the entire question, and counting past two is work whose answer is never used.
    /// </remarks>
    private static async Task<TEntity?> FindSingleMatchAsync<TEntity>(IMongoCollection<TEntity> collection, FilterDefinition<TEntity> filter)
        where TEntity : class
    {
        var entities = await collection.Find(filter).Limit(2).ToListAsync();
        return entities.Count == 1 ? entities[0] : null;
    }
}
