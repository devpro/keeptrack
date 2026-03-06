using System;

namespace KeepTrack.Domain.Models;

public class BookModel : IDataModel
{
    public string Id { get; set; } = string.Empty;

    public string OwnerId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Author { get; set; } = string.Empty;

    public string? Series { get; set; }

    public DateTime? FinishedAt { get; set; }
}
