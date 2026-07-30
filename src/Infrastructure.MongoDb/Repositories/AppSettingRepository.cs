using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// A single settings document (fixed <c>_id</c>) holding every global admin setting - see
/// <see cref="IAppSettingRepository"/> for why this is one shared collection, not one per setting.
/// </summary>
public class AppSettingRepository(IMongoDatabase mongoDatabase) : IAppSettingRepository
{
    private const string CollectionName = "app_setting";

    /// <summary>Fixed id of the one settings document, so every read/write targets the same row.</summary>
    private const string GlobalId = "global";

    private IMongoCollection<AppSetting> Collection => mongoDatabase.GetCollection<AppSetting>(CollectionName);

    public async Task<IReadOnlyDictionary<string, string>> GetReferenceRatingSourcesAsync()
    {
        var entity = await Collection.Find(s => s.Id == GlobalId).FirstOrDefaultAsync();
        return entity?.ReferenceRatingSources ?? new Dictionary<string, string>();
    }

    public async Task SetReferenceRatingSourceAsync(string domainKey, string source)
    {
        // targets just the one map entry so unrelated settings on the same document are never overwritten;
        // upsert creates the document (with _id = "global" taken from the filter) the first time.
        var update = Builders<AppSetting>.Update.Set($"reference_rating_source.{domainKey}", source);
        await Collection.UpdateOneAsync(s => s.Id == GlobalId, update, new UpdateOptions { IsUpsert = true });
    }
}
