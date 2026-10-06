using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Every lookup against <c>matched_aliases</c>, written once for the five reference collections over <see cref="IHasMatchedAliases"/>.
/// The domains differ only in which alias fields make their identity, so each repository picks a method here.
/// <para>
/// Every condition sits in one <c>ElemMatch</c>, since the fields must hold on the <b>same</b> element, or a title from one alias and a year from another would satisfy a query neither confirmed.
/// It also keeps the queries indexed by the compound <c>matched_aliases.*</c> indexes in <c>scripts/mongodb-create-index.js</c>, one per domain lookup.
/// </para>
/// </summary>
internal static class ReferenceAliasQueries
{
    /// <summary>
    /// The reference confirmed under this exact (title, year), the identity of films, shows and games.
    /// </summary>
    /// <remarks>
    /// <c>FirstOrDefault</c>, not <see cref="FindSingleMatchAsync{TEntity}"/>: two documents sharing a title <i>and</i> a year are one work duplicated, so either answers, and refusing would break linking until an admin merged them.
    /// </remarks>
    internal static Task<TEntity?> FindByTitleYearAsync<TEntity>(IMongoCollection<TEntity> collection, string title, int? year)
        where TEntity : class, IHasMatchedAliases =>
        FindFirstAsync(collection, Alias<TEntity>(
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, TitleNormalizer.Normalize(title))
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year)));

    /// <summary>
    /// The reference confirmed under this (title, year, creator): books, whose printings the year tells apart and whose title needs a creator.
    /// </summary>
    internal static Task<TEntity?> FindByTitleYearCreatorAsync<TEntity>(IMongoCollection<TEntity> collection, string title, int? year, string creator)
        where TEntity : class, IHasMatchedAliases =>
        FindFirstAsync(collection, Alias<TEntity>(
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, TitleNormalizer.Normalize(title))
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, TitleNormalizer.Normalize(creator))));

    /// <summary>
    /// The reference confirmed under this (title, creator), whatever year either side records.
    /// It is an album's whole identity, and a book's fallback when the tenant's year names an edition nobody confirmed, the ordinary case since a work is reprinted under many years.
    /// </summary>
    /// <param name="collection"></param>
    /// <param name="title"></param>
    /// <param name="creator"></param>
    /// <param name="refuseAmbiguous">
    /// Whether several matches leave the item unresolved (books, since two works can share a title and an author's name) or either will do (albums, where title and artist are the identity, so two matches are a duplicate to merge).
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
    /// The reference confirmed under this ISBN, books only, the strongest key of the domain.
    /// An ISBN names one printing outright, so it is asked before any title and matches a work recorded under a translated title.
    /// </summary>
    internal static Task<TEntity?> FindByIsbnAsync<TEntity>(IMongoCollection<TEntity> collection, string isbn)
        where TEntity : class, IHasMatchedAliases =>
        FindFirstAsync(collection, Alias<TEntity>(Builders<ReferenceMatch>.Filter.Eq(m => m.Isbn, isbn.Trim())));

    /// <summary>
    /// The <b>single</b> reference carrying this title, or null when none does <b>or several do</b>.
    /// The fallback for films, shows and games when the caller has no year to identify the work.
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
    /// The single document matching <paramref name="filter"/>, or null when none <b>or several</b> match.
    /// <para>
    /// A plain <c>FirstOrDefaultAsync</c> would return whichever namesake the database hands back first, a guess stable enough to look deliberate.
    /// A yearless "Resident Evil 2" would then link one of the eight games IGDB holds under that name.
    /// </para>
    /// <para>
    /// <b>Ambiguous and not found are the same answer to a caller that must not guess</b>, so both are null, which every caller treats as "leave it unresolved".
    /// </para>
    /// </summary>
    /// <remarks>
    /// Reads two documents, never a count, since "more than one" is the whole question.
    /// </remarks>
    private static async Task<TEntity?> FindSingleMatchAsync<TEntity>(IMongoCollection<TEntity> collection, FilterDefinition<TEntity> filter)
        where TEntity : class
    {
        var entities = await collection.Find(filter).Limit(2).ToListAsync();
        return entities.Count == 1 ? entities[0] : null;
    }
}
