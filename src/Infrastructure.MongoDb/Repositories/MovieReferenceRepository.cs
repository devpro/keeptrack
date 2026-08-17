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

public class MovieReferenceRepository(IMongoDatabase mongoDatabase, MovieReferenceStorageMapper mapper) : IMovieReferenceRepository
{
    private const string CollectionName = "movie_reference";

    private IMongoCollection<MovieReference> Collection => mongoDatabase.GetCollection<MovieReference>(CollectionName);

    public async Task<MovieReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        // Mapperly throws on a null source rather than substituting a default instance - checking for a
        // missing document must happen before mapping regardless.
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<MovieReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0) return [];
        var entities = await Collection.Find(Builders<MovieReference>.Filter.In(x => x.Id, ids)).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider) =>
        ExploreExclusionQueries.FindExternalIdsAsync(Collection, ids, provider, x => x.Id, x => x.ExternalIds);

    public Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit) =>
        ReferenceRatingQueries.FindRatingsAsync<MovieReference>(Collection, afterId, limit);

    /// <summary>
    /// Matches against every (title, year) combination ever confirmed for a reference, not just its canonical one - see <see cref="ReferenceAliasQueries"/> for the shared query and why every condition sits in one <c>ElemMatch</c>.
    /// </summary>
    public async Task<MovieReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        var entity = await ReferenceAliasQueries.FindByTitleYearAsync(Collection, title, year);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<MovieReferenceModel?> FindByTitleAsync(string title)
    {
        var entity = await ReferenceAliasQueries.FindByTitleAsync(Collection, title);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<MovieReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        // a string field-path filter, not an expression indexer - the driver's expression-to-filter
        // translation doesn't support indexing a Dictionary<TKey,TValue> by a runtime key.
        var filter = Builders<MovieReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<MovieReferenceModel>> FindStaleAsync(DateTime cutoff, int limit)
    {
        var entities = await ReferenceStalenessQueries.FindStaleAsync(Collection, x => x.LastEnrichedAt, cutoff, limit);
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<List<MovieReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<MovieReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<MovieReferenceModel> UpsertAsync(MovieReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // the canonical (title, year) combination is always itself a valid match, whether or not the caller remembered to include it - but only while it is a complete key, so a film with no year records nothing rather than a title-only alias that would answer for every year (see ReferenceAliasRule)
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
