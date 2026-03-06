namespace KeepTrack.Dal.MongoDb.Entities;

public interface IEntity
{
    public string Id { get; set; }

    string OwnerId { get; set; }
}
