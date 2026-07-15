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

    public async Task<VideoGameReferenceModel?> FindByTitleYearAsync(string title, int? year)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var filter = Builders<VideoGameReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized) & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<VideoGameReferenceModel?> FindByTitleAsync(string title)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var filter = Builders<VideoGameReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<VideoGameReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        var filter = Builders<VideoGameReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<VideoGameReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<VideoGameReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<VideoGameReferenceModel> UpsertAsync(VideoGameReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
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
