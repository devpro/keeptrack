using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
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
        // Mapperly throws on a null source rather than substituting a default instance - checking for a
        // missing document must happen before mapping regardless.
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<TvShowReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        // matches against every known-good (title, year) combination for this reference (see
        // MatchedAliases), not just its canonical TitleNormalized/Year - ElemMatch requires both conditions
        // to hold on the SAME array element, so a tenant whose recorded year genuinely differs from the
        // document's own canonical Year still matches, as long as that exact (title, year) pair was
        // confirmed at some point (automatic resolution or admin pick).
        var normalized = TitleNormalizer.Normalize(title);
        var filter = Builders<TvShowReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized) & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<TvShowReferenceModel?> FindByTitleAsync(string title)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var filter = Builders<TvShowReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<TvShowReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        // a string field-path filter, not an expression indexer - the driver's expression-to-filter
        // translation doesn't support indexing a Dictionary<TKey,TValue> by a runtime key.
        var filter = Builders<TvShowReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<TvShowReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<TvShowReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // the canonical (title, year) combination is always itself a valid match, whether or not the caller
        // remembered to include it
        if (!model.MatchedAliases.Any(m => m.Title == model.TitleNormalized && m.Year == model.Year))
        {
            model.MatchedAliases.Add(new ReferenceMatchModel { Title = model.TitleNormalized, Year = model.Year });
        }
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
}
