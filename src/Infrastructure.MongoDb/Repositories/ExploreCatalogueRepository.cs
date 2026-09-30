using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Persistence for the materialized Explore rankings. Purpose-built (not
/// <see cref="MongoDbRepositoryBase{TModel, TEntity}"/>): the collection is owner-less and read by rank
/// cursor rather than owner-scoped skip/limit.
/// </summary>
public class ExploreCatalogueRepository(IMongoDatabase mongoDatabase, ExploreCatalogueEntryStorageMapper mapper) : IExploreCatalogueRepository
{
    private const string CollectionName = "explore_catalogue";

    private IMongoCollection<ExploreCatalogueEntry> Collection => mongoDatabase.GetCollection<ExploreCatalogueEntry>(CollectionName);

    public async Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindRankedAsync(ExploreItemType type, string ranking, int afterRank, int take)
    {
        var entities = await Collection
            .Find(RankingFilter(type, ranking) & Builders<ExploreCatalogueEntry>.Filter.Gt(e => e.Rank, afterRank))
            .SortBy(e => e.Rank)
            .Limit(take)
            .ToListAsync();
        return mapper.ToModels(entities);
    }

    public async Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindMissingRatingOrLinkAsync(
        ExploreItemType type, string ranking, string source, DateTime notAttemptedSince, int take)
    {
        var builder = Builders<ExploreCatalogueEntry>.Filter;

        // no value yet, and not asked about recently enough to be worth re-asking
        var ratingPending = builder.Exists(RatingField(source), false)
                            & (builder.Exists(AttemptField(source), false)
                               | builder.Lt<DateTime>(AttemptField(source), notAttemptedSince));

        // has a rating but no link: a pass from before links were stored resolved the provider id and then
        // dropped it. One lookup fixes it permanently, so this half needs no re-attempt window - and can't
        // loop, because "the provider has no id for this title" implies no rating either, which is the
        // windowed branch above. See IExploreCatalogueRepository for the full argument.
        var linkPending = builder.Exists(WebUrlField(source), false) & builder.Exists(RatingField(source));

        var entities = await Collection
            .Find(RankingFilter(type, ranking) & (ratingPending | linkPending))
            .SortBy(e => e.Rank)
            .Limit(take)
            .ToListAsync();
        return mapper.ToModels(entities);
    }

    public async Task UpsertManyAsync(IReadOnlyList<ExploreCatalogueEntryModel> entries)
    {
        if (entries.Count == 0) return;

        var writes = entries.Select(entry =>
        {
            var entity = mapper.ToEntity(entry);
            var update = Builders<ExploreCatalogueEntry>.Update
                .Set(e => e.Rank, entity.Rank)
                .Set(e => e.Title, entity.Title)
                .Set(e => e.Year, entity.Year)
                .Set(e => e.Synopsis, entity.Synopsis)
                .Set(e => e.ImageUrl, entity.ImageUrl)
                .Set(e => e.RefreshedAt, entity.RefreshedAt);

            // one targeted $set per rating key rather than replacing the whole "ratings" subdocument: a
            // refresh only knows the ratings its own listing carried, and blanking the rest would throw away
            // the backfilled values (IMDb) that cost a separate provider call to obtain.
            update = entity.Ratings.Aggregate(update, (current, rating) => current.Set(RatingField(rating.Key), rating.Value));

            // same reasoning for the links: a listing carries its own provider's page and nothing else, so
            // replacing the map would drop the backfilled IMDb link on every weekly refresh.
            update = entity.WebUrls.Aggregate(update, (current, link) => current.Set(WebUrlField(link.Key), link.Value));

            // the natural-key fields are deliberately not $set here: an upsert whose filter is pure equality
            // copies those fields into the document it inserts (the same mechanism LeaseRepository relies on
            // for its _id), so naming them twice would only risk a conflicting-path update error.
            return new UpdateOneModel<ExploreCatalogueEntry>(KeyFilter(entry.ItemType, entry.Ranking, entry.ExternalId), update) { IsUpsert = true };
        }).ToList();

        // unordered: the writes are independent per entry, so one failure doesn't abandon the rest of the page
        await Collection.BulkWriteAsync(writes, new BulkWriteOptions { IsOrdered = false });
    }

    public async Task RecordRatingAttemptAsync(ExploreItemType type, string ranking, string externalId, string ratingSource, double? value)
    {
        var update = Builders<ExploreCatalogueEntry>.Update.Set<DateTime>(AttemptField(ratingSource), DateTime.UtcNow);
        if (value is not null) update = update.Set(RatingField(ratingSource), value.Value);

        await Collection.UpdateOneAsync(KeyFilter(type, ranking, externalId), update);
    }

    public Task SetWebUrlAsync(ExploreItemType type, string ranking, string externalId, string source, string webUrl) =>
        Collection.UpdateOneAsync(
            KeyFilter(type, ranking, externalId),
            Builders<ExploreCatalogueEntry>.Update.Set(WebUrlField(source), webUrl));

    public async Task<long> DeleteStaleAsync(ExploreItemType type, string ranking, DateTime refreshedBefore)
    {
        var filter = RankingFilter(type, ranking) & Builders<ExploreCatalogueEntry>.Filter.Lt(e => e.RefreshedAt, refreshedBefore);
        var result = await Collection.DeleteManyAsync(filter);
        return result.DeletedCount;
    }

    public async Task<DateTime?> FindOldestRefreshedAtAsync(ExploreItemType type, string ranking)
    {
        var entity = await Collection.Find(RankingFilter(type, ranking)).SortBy(e => e.RefreshedAt).Limit(1).FirstOrDefaultAsync();
        return entity?.RefreshedAt;
    }

    public Task<long> CountAsync(ExploreItemType type, string ranking) => Collection.CountDocumentsAsync(RankingFilter(type, ranking));

    public async Task<long> DeleteRankingsExceptAsync(IReadOnlyCollection<string> rankings)
    {
        // an empty keep-set would delete the whole catalogue; that can only mean a caller bug, and emptying
        // Explore is far worse than leaving it as it is
        if (rankings.Count == 0) return 0;

        // filtered on the ranking key alone, not on (type, ranking): a ranking key names a provider's ordering
        // and is unique across domains, so there is no pair to enumerate
        var result = await Collection.DeleteManyAsync(Builders<ExploreCatalogueEntry>.Filter.Nin(e => e.Ranking, rankings));
        return result.DeletedCount;
    }

    // the (domain, ordering) prefix every query is scoped to, and the full natural key - shared so a read, a
    // write and a prune can never disagree on what identifies an entry.
    private static FilterDefinition<ExploreCatalogueEntry> RankingFilter(ExploreItemType type, string ranking) =>
        Builders<ExploreCatalogueEntry>.Filter.Eq(e => e.ItemType, type)
        & Builders<ExploreCatalogueEntry>.Filter.Eq(e => e.Ranking, ranking);

    private static FilterDefinition<ExploreCatalogueEntry> KeyFilter(ExploreItemType type, string ranking, string externalId) =>
        RankingFilter(type, ranking) & Builders<ExploreCatalogueEntry>.Filter.Eq(e => e.ExternalId, externalId);

    // dotted paths into the per-source maps. A string field name is correct here (these are genuine dynamic
    // dictionary keys, not a typed member) - unlike an _id filter, where the string form silently matches
    // nothing; see DatabaseTestBase.TrackDocument.
    private static string RatingField(string source) => $"ratings.{source}";

    private static string AttemptField(string source) => $"ratings_checked_at.{source}";

    private static string WebUrlField(string source) => $"web_urls.{source}";
}
