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
    /// Matches against every (title, artist) combination ever confirmed for a reference, not just its canonical one - see <see cref="ReferenceAliasQueries"/> for the shared query.
    /// The year takes no part: it is not in an album's identity (see <see cref="ReferenceAliasRule.TitleAndCreator"/>), so an alias written under one pressing's year still answers a tenant who recorded another's.
    /// </summary>
    public async Task<AlbumReferenceModel?> FindByTitleCreatorAsync(string title, string artist)
    {
        // not refuseAmbiguous: title + artist IS the identity here, so two matching documents are a duplicate to merge rather than an ambiguity - either one answers the question, same as a title+year pair.
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
        // No canonical-alias safety net here - see BookReferenceRepository.UpsertAsync's equivalent comment: an album is identified by title + artist and this model carries only ArtistReferenceId, so the (title, year) pair it used to add was an artist-less half-key on every album reference ever upserted.
        // ReferenceAliasRule.TitleAndCreator is what the Resolve/Refresh paths write instead.
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
