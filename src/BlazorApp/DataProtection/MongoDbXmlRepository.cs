using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Keeptrack.BlazorApp.DataProtection;

/// <summary>
/// Persists the ASP.NET Core Data Protection key ring in MongoDB, so every replica of this app encrypts and decrypts with the same keys.
/// Otherwise each pod generates its own ephemeral key ring, and an auth cookie (carrying the user's Firebase token) issued by one replica is unreadable to another.
/// Antiforgery tokens fail the same way, which blocks running more than one replica however traffic is routed.
/// MongoDB is the one shared store the system always has, so no ReadWriteMany volume or extra service is needed.
/// Keys are stored unencrypted at rest, like the framework's file-system default on Linux, the database being already the deployment's most sensitive store.
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
        /// <summary>The framework-provided friendly name ("key-{guid}"), unique per key.</summary>
        [BsonId]
        public required string Id { get; set; }

        public required string Xml { get; set; }
    }
}
