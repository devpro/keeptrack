using KeepTrack.Common.Collections.Generic;

namespace KeepTrack.WebApi.Contracts.Dto;

public class MovieDto: IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public int? Year { get; set; }

    public int? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Notes { get; set; }

    public string? ImdbPageId { get; set; }

    public string? AllocineId { get; set; }
}
