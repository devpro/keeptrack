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
/// Persistence for the stored Explore rankings.
/// Not a <see cref="MongoDbRepositoryBase{TModel, TEntity}"/>, since the collection is owner-less and read by rank cursor rather than owner-scoped skip and limit.
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

        // a rating without a link: one lookup fixes it for good, so no window is needed, and it cannot loop, since a title with no provider id has no rating either (see IExploreCatalogueRepository)
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

            // one $set per rating key rather than replacing "ratings": a refresh only knows its listing's ratings, and replacing would discard backfilled IMDb values that cost a provider call
            update = entity.Ratings.Aggregate(update, (current, rating) => current.Set(RatingField(rating.Key), rating.Value));

            // same for links: a listing carries only its provider's page, so replacing the map would drop the backfilled IMDb link on every refresh
            update = entity.WebUrls.Aggregate(update, (current, link) => current.Set(WebUrlField(link.Key), link.Value));

            // the natural-key fields are not $set: an upsert with an equality filter copies them into the inserted document, and naming them twice risks a conflicting-path error
            return new UpdateOneModel<ExploreCatalogueEntry>(KeyFilter(entry.ItemType, entry.Ranking, entry.ExternalId), update) { IsUpsert = true };
        }).ToList();

        // unordered, since the writes are independent, so one failure does not abandon the rest of the page
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
        // an empty keep-set would delete the whole catalogue, which can only be a caller bug, and emptying Explore is far worse than leaving it
        if (rankings.Count == 0) return 0;

        // filtered on the ranking key alone, which is unique across domains, so there is no (type, ranking) pair to enumerate
        var result = await Collection.DeleteManyAsync(Builders<ExploreCatalogueEntry>.Filter.Nin(e => e.Ranking, rankings));
        return result.DeletedCount;
    }

    // the (domain, ordering) prefix and the full natural key, shared so reads, writes and prunes agree on what identifies an entry
    private static FilterDefinition<ExploreCatalogueEntry> RankingFilter(ExploreItemType type, string ranking) =>
        Builders<ExploreCatalogueEntry>.Filter.Eq(e => e.ItemType, type)
        & Builders<ExploreCatalogueEntry>.Filter.Eq(e => e.Ranking, ranking);

    private static FilterDefinition<ExploreCatalogueEntry> KeyFilter(ExploreItemType type, string ranking, string externalId) =>
        RankingFilter(type, ranking) & Builders<ExploreCatalogueEntry>.Filter.Eq(e => e.ExternalId, externalId);

    // dotted paths into the per-source maps, as strings since these are dynamic dictionary keys rather than typed members
    private static string RatingField(string source) => $"ratings.{source}";

    private static string AttemptField(string source) => $"ratings_checked_at.{source}";

    private static string WebUrlField(string source) => $"web_urls.{source}";
}
