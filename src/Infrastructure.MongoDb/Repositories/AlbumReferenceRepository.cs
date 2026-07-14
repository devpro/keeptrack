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

public class AlbumReferenceRepository(IMongoDatabase mongoDatabase, AlbumReferenceStorageMapper mapper) : IAlbumReferenceRepository
{
    private const string CollectionName = "album_reference";

    private IMongoCollection<AlbumReference> Collection => mongoDatabase.GetCollection<AlbumReference>(CollectionName);

    public async Task<AlbumReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<AlbumReferenceModel?> FindByTitleYearAsync(string title, int? year, string artist)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var normalizedArtist = TitleNormalizer.Normalize(artist);
        var filter = Builders<AlbumReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, normalizedArtist));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<AlbumReferenceModel?> FindByTitleAsync(string title, string artist)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var normalizedArtist = TitleNormalizer.Normalize(artist);
        var filter = Builders<AlbumReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, normalizedArtist));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<AlbumReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        var filter = Builders<AlbumReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<AlbumReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<AlbumReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<AlbumReferenceModel> UpsertAsync(AlbumReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // see BookReferenceRepository.UpsertAsync's equivalent comment - this safety net can't know the
        // canonical artist text (the model only carries ArtistReferenceId), so it's harmless dead weight
        // when hit, not a false-positive risk.
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
