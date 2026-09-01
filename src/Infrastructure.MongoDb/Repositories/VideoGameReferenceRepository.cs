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

public class VideoGameReferenceRepository(IMongoDatabase mongoDatabase, VideoGameReferenceStorageMapper mapper) : IVideoGameReferenceRepository
{
    private const string CollectionName = "videogame_reference";

    private IMongoCollection<VideoGameReference> Collection => mongoDatabase.GetCollection<VideoGameReference>(CollectionName);

    public async Task<VideoGameReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<VideoGameReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0) return [];
        var entities = await Collection.Find(Builders<VideoGameReference>.Filter.In(x => x.Id, ids)).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider) =>
        ExploreExclusionQueries.FindExternalIdsAsync(Collection, ids, provider, x => x.Id, x => x.ExternalIds);

    public Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit) =>
        ReferenceRatingQueries.FindRatingsAsync<VideoGameReference>(Collection, afterId, limit);

    /// <summary>
    /// Matches against every (title, year) combination ever confirmed for a reference, not just its canonical one - see <see cref="ReferenceAliasQueries"/> for the shared query and why every condition sits in one <c>ElemMatch</c>.
    /// </summary>
    public async Task<VideoGameReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        var entity = await ReferenceAliasQueries.FindByTitleYearAsync(Collection, title, year);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<VideoGameReferenceModel?> FindByTitleAsync(string title)
    {
        var entity = await ReferenceAliasQueries.FindByTitleAsync(Collection, title);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<VideoGameReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        var filter = Builders<VideoGameReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<VideoGameReferenceModel>> FindStaleAsync(DateTime cutoff, int limit)
    {
        var entities = await ReferenceStalenessQueries.FindStaleAsync(Collection, x => x.LastEnrichedAt, cutoff, limit);
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<List<VideoGameReferenceModel>> FindWithoutExternalIdAsync(string provider)
    {
        // Exists:false rather than Eq(null): a document written before this provider existed simply has no
        // such key, and the same "a missing field is not a null field" trap the staleness query documents
        // applies here - only Exists matches both a missing key and one explicitly set to null.
        var filter = Builders<VideoGameReference>.Filter.Exists($"external_ids.{provider}", false);
        var entities = await Collection.Find(filter).SortBy(x => x.Title).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<List<VideoGameReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<VideoGameReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<VideoGameReferenceModel> UpsertAsync(VideoGameReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // the canonical (title, year) combination is always itself a valid match, whether or not the caller remembered to include it - but only while it is a complete key.
        // A game with no year records nothing: IGDB holds eight named exactly "Resident Evil 2", and the title-only alias this used to write for them answered every later lookup for that title, whatever year it carried (see ReferenceAliasRule).
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
