using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class ShareRepository(IMongoDatabase mongoDatabase, ShareStorageMapper mapper) : IShareRepository
{
    private const string CollectionName = "share";

    private IMongoCollection<Share> Collection => mongoDatabase.GetCollection<Share>(CollectionName);

    public async Task<List<ShareModel>> FindAllByOwnerIdAsync(string ownerId)
    {
        var entities = await Collection.Find(s => s.OwnerId == ownerId).SortBy(s => s.CreatedAt).ToListAsync();
        return entities.ConvertAll(mapper.ToModel);
    }

    public async Task<List<ShareModel>> FindAllByRecipientEmailAsync(string recipientEmail)
    {
        var entities = await Collection.Find(s => s.RecipientEmail == recipientEmail).SortBy(s => s.CreatedAt).ToListAsync();
        return entities.ConvertAll(mapper.ToModel);
    }

    public async Task<ShareModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(s => s.Id == id).FirstOrDefaultAsync();
        // the usual null guard before mapping - see MongoDbRepositoryBase.FindOneAsync's identical shape
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<ShareModel> CreateAsync(ShareModel model)
    {
        var entity = mapper.ToEntity(model);
        entity.CreatedAt = DateTime.UtcNow;
        await Collection.InsertOneAsync(entity);
        return mapper.ToModel(entity);
    }

    public async Task DeleteAsync(string id, string ownerId) =>
        await Collection.DeleteOneAsync(s => s.Id == id && s.OwnerId == ownerId);
}
