using System.Threading.Tasks;
using AutoMapper;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class MovieReferenceRepository(IMongoDatabase mongoDatabase, IMapper mapper) : IMovieReferenceRepository
{
    private const string CollectionName = "movie_reference";

    private IMongoCollection<MovieReference> Collection => mongoDatabase.GetCollection<MovieReference>(CollectionName);

    public async Task<MovieReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        return mapper.Map<MovieReferenceModel>(entity);
    }

    public async Task<MovieReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        var filter = Builders<MovieReference>.Filter.Eq(x => x.TitleNormalized, TitleNormalizer.Normalize(title))
                     & Builders<MovieReference>.Filter.Eq(x => x.Year, year);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return mapper.Map<MovieReferenceModel>(entity);
    }

    public async Task<MovieReferenceModel> UpsertAsync(MovieReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        var entity = mapper.Map<MovieReference>(model);

        if (string.IsNullOrEmpty(entity.Id))
        {
            await Collection.InsertOneAsync(entity);
        }
        else
        {
            await Collection.ReplaceOneAsync(x => x.Id == entity.Id, entity, new ReplaceOptions { IsUpsert = true });
        }

        return mapper.Map<MovieReferenceModel>(entity);
    }
}
