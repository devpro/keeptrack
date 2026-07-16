using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// MongoDB-backed job progress, replacing the old in-memory store: any replica can answer a status poll
/// for a job another replica is running, and jobs survive an app restart. Every update is a targeted
/// <c>$set</c> (never read-modify-write), so a poller and the job runner can't race each other.
/// </summary>
public class BackgroundJobRepository(IMongoDatabase mongoDatabase, BackgroundJobStorageMapper mapper) : IBackgroundJobRepository
{
    private const string CollectionName = "background_job";

    private IMongoCollection<BackgroundJob> Collection => mongoDatabase.GetCollection<BackgroundJob>(CollectionName);

    public async Task CreateAsync(BackgroundJobModel job)
    {
        var entity = mapper.ToEntity(job);
        entity.CreatedAt = DateTime.UtcNow;
        await Collection.InsertOneAsync(entity);
    }

    public async Task UpdateStageAsync(Guid jobId, string stage) =>
        await Collection.UpdateOneAsync(
            Builders<BackgroundJob>.Filter.Eq(j => j.Id, jobId.ToString()),
            Builders<BackgroundJob>.Update.Set(j => j.Stage, stage));

    public async Task CompleteAsync(Guid jobId, string stage, string resultJson) =>
        await Collection.UpdateOneAsync(
            Builders<BackgroundJob>.Filter.Eq(j => j.Id, jobId.ToString()),
            Builders<BackgroundJob>.Update.Set(j => j.Stage, stage).Set(j => j.ResultJson, resultJson));

    public async Task FailAsync(Guid jobId, string stage, string errorMessage) =>
        await Collection.UpdateOneAsync(
            Builders<BackgroundJob>.Filter.Eq(j => j.Id, jobId.ToString()),
            Builders<BackgroundJob>.Update.Set(j => j.Stage, stage).Set(j => j.ErrorMessage, errorMessage));

    public async Task<BackgroundJobModel?> FindAsync(Guid jobId, string ownerId)
    {
        var filter = Builders<BackgroundJob>.Filter.Eq(j => j.Id, jobId.ToString())
                     & Builders<BackgroundJob>.Filter.Eq(j => j.OwnerId, ownerId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        // the usual null guard before mapping - see MongoDbRepositoryBase.FindOneAsync's identical shape
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<BackgroundJobModel>> FindRecentAsync(int limit)
    {
        var entities = await Collection
            .Find(FilterDefinition<BackgroundJob>.Empty)
            .SortByDescending(j => j.CreatedAt)
            .Limit(limit)
            .ToListAsync();
        return entities.ConvertAll(mapper.ToModel);
    }
}
