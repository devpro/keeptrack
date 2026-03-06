namespace KeepTrack.Domain.Models;

public class MovieModel : IDataModel
{
    public string Id { get; set; }

    public string OwnerId { get; set; }

    public string Title { get; set; }

    public int? Year { get; set; }

    public string ImdbPageId { get; set; }

    public string AllocineId { get; set; }
}
