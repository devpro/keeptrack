using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class PersonReferenceRepository(IMongoDatabase mongoDatabase, PersonReferenceStorageMapper mapper) : IPersonReferenceRepository
{
    private const string CollectionName = "person_reference";

    private IMongoCollection<PersonReference> Collection => mongoDatabase.GetCollection<PersonReference>(CollectionName);

    public async Task<PersonReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        // Mapperly throws on a null source rather than substituting a default instance - checking for a
        // missing document must happen before mapping regardless.
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<PersonReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        // a string field-path filter, not an expression indexer - the driver's expression-to-filter
        // translation doesn't support indexing a Dictionary<TKey,TValue> by a runtime key.
        var filter = Builders<PersonReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<PersonReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<PersonReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<PersonReferenceModel> UpsertAsync(PersonReferenceModel model)
    {
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
