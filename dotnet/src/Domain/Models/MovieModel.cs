namespace KeepTrack.Domain.Models;

public class MovieModel : IDataModel
{
    public string Id { get; set; } = null!;

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? ImdbPageId { get; set; }

    public string? AllocineId { get; set; }
}
