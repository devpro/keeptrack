namespace KeepTrack.Domain.Models;

public class TvShowModel : IDataModel
{
    public string Id { get; set; } = string.Empty;

    public string OwnerId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;
}
