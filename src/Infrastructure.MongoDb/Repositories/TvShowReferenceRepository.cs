using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class TvShowReferenceRepository(IMongoDatabase mongoDatabase, TvShowReferenceStorageMapper mapper) : ITvShowReferenceRepository
{
    private const string CollectionName = "tvshow_reference";

    private IMongoCollection<TvShowReference> Collection => mongoDatabase.GetCollection<TvShowReference>(CollectionName);

    public async Task<TvShowReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        // Mapperly throws on a null source rather than substituting a default instance - checking for a missing document must happen before mapping regardless.
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<TvShowReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0) return [];
        var entities = await Collection.Find(Builders<TvShowReference>.Filter.In(x => x.Id, ids)).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider) =>
        ExploreExclusionQueries.FindExternalIdsAsync(Collection, ids, provider, x => x.Id, x => x.ExternalIds);

    public Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit) =>
        ReferenceRatingQueries.FindRatingsAsync<TvShowReference>(Collection, afterId, limit);

    /// <summary>
    /// Matches against every (title, year) combination ever confirmed for a reference, not just its canonical one - see <see cref="ReferenceAliasQueries"/> for the shared query and why every condition sits in one <c>ElemMatch</c>.
    /// </summary>
    public async Task<TvShowReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        var entity = await ReferenceAliasQueries.FindByTitleYearAsync(Collection, title, year);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<TvShowReferenceModel?> FindByTitleAsync(string title)
    {
        var entity = await ReferenceAliasQueries.FindByTitleAsync(Collection, title);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<TvShowReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        // a string field-path filter, not an expression indexer - the driver's expression-to-filter translation doesn't support indexing a Dictionary<TKey,TValue> by a runtime key.
        var filter = Builders<TvShowReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<TvShowReferenceModel>> FindStaleAsync(DateTime cutoff, int limit)
    {
        var entities = await ReferenceStalenessQueries.FindStaleAsync(Collection, x => x.LastEnrichedAt, cutoff, limit);
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<List<TvShowReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<TvShowReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // the canonical (title, year) combination is always itself a valid match, whether or not the caller remembered to include it - but only while it is a complete key, so a show with no year records nothing rather than a title-only alias that would answer for every year (see ReferenceAliasRule)
        ReferenceAliasRule.TitleAndYear.EnsureCanonical(model.MatchedAliases, model.TitleNormalized, model.Year);
        var entity = mapper.ToEntity(model);

        if (string.IsNullOrEmpty(entity.Id))
        {
            await Collection.InsertOneAsync(entity);
        }
        else
        {
            await Collection.ReplaceOneAsync(x => x.Id == entity.Id, entity, new ReplaceOptions { IsUpsert = true });
        }

        return mapper.ToModel(entity);
    }

    public async Task DeleteAsync(string id)
    {
        await Collection.DeleteOneAsync(x => x.Id == id);
    }
}
