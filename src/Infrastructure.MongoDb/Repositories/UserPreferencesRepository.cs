using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class UserPreferencesRepository(IMongoDatabase mongoDatabase, UserPreferencesStorageMapper mapper) : IUserPreferencesRepository
{
    private const string CollectionName = "user_preference";

    private IMongoCollection<UserPreferences> Collection => mongoDatabase.GetCollection<UserPreferences>(CollectionName);

    public async Task<UserPreferencesModel?> FindByOwnerIdAsync(string ownerId)
    {
        var entity = await Collection.Find(x => x.OwnerId == ownerId).FirstOrDefaultAsync();
        // the usual null guard before mapping - see MongoDbRepositoryBase.FindOneAsync's identical shape
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task UpsertAsync(UserPreferencesModel model)
    {
        var entity = mapper.ToEntity(model);
        await Collection.ReplaceOneAsync(x => x.OwnerId == model.OwnerId, entity, new ReplaceOptions { IsUpsert = true });
    }
}
