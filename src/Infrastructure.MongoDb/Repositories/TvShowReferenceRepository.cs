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
        var filter = Builders<TvShowReference>.Filter.Eq(x => x.TitleNormalized, TitleNormalizer.Normalize(title))
                     & Builders<TvShowReference>.Filter.Eq(x => x.Year, year);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.Map<TvShowReferenceModel>(entity);
    }

    public async Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
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
