using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// One settings document with a fixed <c>_id</c>, holding every global admin setting (see <see cref="IAppSettingRepository"/>).
/// </summary>
public class AppSettingRepository(IMongoDatabase mongoDatabase) : IAppSettingRepository
{
    private const string CollectionName = "app_setting";

    /// <summary>The fixed id of the one settings document, which every read and write targets.</summary>
    private const string GlobalId = "global";

    private IMongoCollection<AppSetting> Collection => mongoDatabase.GetCollection<AppSetting>(CollectionName);

    public async Task<IReadOnlyDictionary<string, string>> GetReferenceRatingSourcesAsync()
    {
        var entity = await Collection.Find(s => s.Id == GlobalId).FirstOrDefaultAsync();
        return entity?.ReferenceRatingSources ?? new Dictionary<string, string>();
    }

    public async Task SetReferenceRatingSourceAsync(string domainKey, string source)
    {
        // targets the one map entry, so other settings of the document are never overwritten, and the upsert creates the document with the filter's _id the first time
        var update = Builders<AppSetting>.Update.Set($"reference_rating_source.{domainKey}", source);
        await Collection.UpdateOneAsync(s => s.Id == GlobalId, update, new UpdateOptions { IsUpsert = true });
    }

    public async Task<bool> GetExploreUseTmdbAsync()
    {
        var entity = await Collection.Find(s => s.Id == GlobalId).FirstOrDefaultAsync();
        return entity?.ExploreUseTmdb ?? false;
    }

    public async Task SetExploreUseTmdbAsync(bool useTmdb)
    {
        // a targeted $set on this field alone, like the rating source setter
        var update = Builders<AppSetting>.Update.Set(s => s.ExploreUseTmdb, useTmdb);
        await Collection.UpdateOneAsync(s => s.Id == GlobalId, update, new UpdateOptions { IsUpsert = true });
    }
}
