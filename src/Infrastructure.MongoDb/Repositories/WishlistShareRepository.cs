using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class WishlistShareRepository(IMongoDatabase mongoDatabase, WishlistShareStorageMapper mapper) : IWishlistShareRepository
{
    private const string CollectionName = "wishlist_share";

    private IMongoCollection<WishlistShare> Collection => mongoDatabase.GetCollection<WishlistShare>(CollectionName);

    public async Task<List<WishlistShareModel>> FindAllByOwnerIdAsync(string ownerId)
    {
        var entities = await Collection.Find(s => s.OwnerId == ownerId).SortBy(s => s.CreatedAt).ToListAsync();
        return entities.ConvertAll(mapper.ToModel);
    }

    public async Task<WishlistShareModel?> FindByTokenAsync(string token)
    {
        var entity = await Collection.Find(s => s.Token == token).FirstOrDefaultAsync();
        // the usual null guard before mapping - see MongoDbRepositoryBase.FindOneAsync's identical shape
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<WishlistShareModel> CreateAsync(WishlistShareModel model)
    {
        var entity = mapper.ToEntity(model);
        entity.CreatedAt = DateTime.UtcNow;
        await Collection.InsertOneAsync(entity);
        return mapper.ToModel(entity);
    }

    public async Task DeleteAsync(string id, string ownerId) =>
        await Collection.DeleteOneAsync(s => s.Id == id && s.OwnerId == ownerId);
}
