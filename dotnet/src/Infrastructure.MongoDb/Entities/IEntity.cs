namespace KeepTrack.Infrastructure.MongoDb.Entities;

public interface IEntity
{
    public string Id { get; }

    public string OwnerId { get; }
}
