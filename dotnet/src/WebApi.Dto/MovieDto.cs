namespace KeepTrack.WebApi.Dto;

/// <summary>
/// Movie data transfer object.
/// </summary>
public class MovieDto
{
    /// <summary>
    /// Movie ID.
    /// </summary>
    public string Id { get; set; }

    /// <summary>
    /// Title.
    /// </summary>
    public string Title { get; set; }

    /// <summary>
    /// Year.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>
    /// IMDB ID.
    /// </summary>
    public string ImdbPageId { get; set; }

    /// <summary>
    /// Allocine ID.
    /// </summary>
    public string AllocineId { get; set; }
}
