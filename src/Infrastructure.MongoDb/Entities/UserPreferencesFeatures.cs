using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class UserPreferencesFeatures
{
    [BsonElement("show_chasse_aux_livres_link")]
    public bool ShowChasseAuxLivresLink { get; set; }

    [BsonElement("show_amazon_product_link")]
    public bool ShowAmazonProductLink { get; set; }
}
