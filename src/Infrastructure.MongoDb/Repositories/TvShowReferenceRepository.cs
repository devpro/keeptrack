using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class TvShowReferenceRepository(IMongoDatabase mongoDatabase, IMapper mapper) : ITvShowReferenceRepository
{
    private const string CollectionName = "tvshow_reference";

    private IMongoCollection<TvShowReference> Collection => mongoDatabase.GetCollection<TvShowReference>(CollectionName);

    public async Task<TvShowReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        // AutoMapper's AllowNullDestinationValues = false (Program.cs) makes Map<T>(null) return a new,
        // all-default instance instead of null - checking for a missing document must happen before mapping.
        return entity is null ? null : mapper.Map<TvShowReferenceModel>(entity);
    }

    public async Task<TvShowReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        // matches against every known-good title variant for this reference (see MatchedTitles), not just
        // its canonical TitleNormalized - AnyEq generates an array-contains filter (matched_titles is a
        // multikey index), so a differently-titled tenant that previously resolved to this same reference
        // is found instantly, with no fresh TMDB search.
        var filter = Builders<TvShowReference>.Filter.AnyEq(x => x.MatchedTitles, TitleNormalizer.Normalize(title))
                     & Builders<TvShowReference>.Filter.Eq(x => x.Year, year);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.Map<TvShowReferenceModel>(entity);
    }

    public async Task<TvShowReferenceModel?> FindByTitleAsync(string title)
    {
        var filter = Builders<TvShowReference>.Filter.AnyEq(x => x.MatchedTitles, TitleNormalizer.Normalize(title));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.Map<TvShowReferenceModel>(entity);
    }

    public async Task<TvShowReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        // a string field-path filter, not an expression indexer - the driver's expression-to-filter
        // translation doesn't support indexing a Dictionary<TKey,TValue> by a runtime key.
        var filter = Builders<TvShowReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.Map<TvShowReferenceModel>(entity);
    }

    public async Task<List<TvShowReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<TvShowReference>.Empty).ToListAsync();
        return entities.Select(mapper.Map<TvShowReferenceModel>).ToList();
    }

    public async Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // the canonical title is always itself a valid match, whether or not the caller remembered to include it
        if (!model.MatchedTitles.Contains(model.TitleNormalized)) model.MatchedTitles.Add(model.TitleNormalized);
        var entity = mapper.Map<TvShowReference>(model);

        if (string.IsNullOrEmpty(entity.Id))
        {
            await Collection.InsertOneAsync(entity);
        }
        else
        {
            await Collection.ReplaceOneAsync(x => x.Id == entity.Id, entity, new ReplaceOptions { IsUpsert = true });
        }

        return mapper.Map<TvShowReferenceModel>(entity);
    }
}
