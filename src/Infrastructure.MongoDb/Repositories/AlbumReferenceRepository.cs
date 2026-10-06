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

public class AlbumReferenceRepository(IMongoDatabase mongoDatabase, AlbumReferenceStorageMapper mapper) : IAlbumReferenceRepository
{
    private const string CollectionName = "album_reference";

    private IMongoCollection<AlbumReference> Collection => mongoDatabase.GetCollection<AlbumReference>(CollectionName);

    public async Task<AlbumReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<AlbumReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0) return [];
        var entities = await Collection.Find(Builders<AlbumReference>.Filter.In(x => x.Id, ids)).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    /// <summary>
    /// Matches every (title, artist) combination confirmed for a reference, not only its canonical one (see <see cref="ReferenceAliasQueries"/>).
    /// The year takes no part, being outside an album's identity (see <see cref="ReferenceAliasRule.TitleAndCreator"/>), so one pressing's alias answers a tenant who recorded another.
    /// </summary>
    public async Task<AlbumReferenceModel?> FindByTitleCreatorAsync(string title, string artist)
    {
        // title and artist are the identity, so two matching documents are a duplicate to merge rather than an ambiguity, and either one answers
        var entity = await ReferenceAliasQueries.FindByTitleCreatorAsync(Collection, title, artist, refuseAmbiguous: false);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<AlbumReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        var filter = Builders<AlbumReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<AlbumReferenceModel>> FindStaleAsync(DateTime cutoff, int limit)
    {
        var entities = await ReferenceStalenessQueries.FindStaleAsync(Collection, x => x.LastEnrichedAt, cutoff, limit);
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<List<AlbumReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<AlbumReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<AlbumReferenceModel> UpsertAsync(AlbumReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // No canonical-alias safety net: an album is its title and artist, and this model carries only ArtistReferenceId, so a complete key cannot be built here.
        // The resolve and refresh paths write the alias through ReferenceAliasRule.TitleAndCreator instead.
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
