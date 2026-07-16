using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Keeptrack.BlazorApp.DataProtection;

/// <summary>
/// Persists the ASP.NET Core Data Protection key ring in MongoDB, so every replica of this app encrypts
/// and decrypts with the same keys. Without this, each pod generates its own ephemeral key ring: an auth
/// cookie (which also carries the user's Firebase token) issued by one replica is undecipherable garbage
/// to another, and antiforgery tokens fail the same way - the hard blocker for running more than one
/// replica, regardless of how traffic is routed (cloudflared, Traefik, anything). MongoDB is used because
/// it's the one shared store this system always has; no ReadWriteMany volume or extra service needed.
/// Keys are stored unencrypted at rest, exactly like the framework's own file-system default on Linux -
/// the database is already the deployment's most sensitive store.
/// </summary>
public class MongoDbXmlRepository(IMongoCollection<MongoDbXmlRepository.DataProtectionKey> collection) : IXmlRepository
{
    public const string CollectionName = "data_protection_keys";

    public IReadOnlyCollection<XElement> GetAllElements() =>
        collection.Find(FilterDefinition<DataProtectionKey>.Empty).ToList()
            .Select(key => XElement.Parse(key.Xml))
            .ToList();

    public void StoreElement(XElement element, string friendlyName) =>
        // upsert by the framework's own key name so a retried store can't duplicate a key
        collection.ReplaceOne(
            Builders<DataProtectionKey>.Filter.Eq(key => key.Id, friendlyName),
            new DataProtectionKey { Id = friendlyName, Xml = element.ToString(SaveOptions.DisableFormatting) },
            new ReplaceOptions { IsUpsert = true });

    public class DataProtectionKey
    {
        /// <summary>The framework-provided friendly name (e.g. "key-{guid}"), unique per key.</summary>
        [BsonId]
        public required string Id { get; set; }

        public required string Xml { get; set; }
    }
}
