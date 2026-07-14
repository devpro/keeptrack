using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class EpisodeCommentRecord
{
    [Name("tv_show_name")]
    public required string ShowTitle { get; set; }

    [Name("episode_season_number")]
    public required int SeasonNumber { get; set; }

    [Name("episode_number")]
    public required int EpisodeNumber { get; set; }

    [Name("comment")]
    public required string Comment { get; set; }

    [Name("created_at")]
    public required DateTime CreatedAt { get; set; }
}

/// <summary>
/// Parses TV Time's episode_comment.csv: the exporting user's own free-text comments on episodes.
/// Episodes here are only identified by show name (no show id in this file), same as seen_episode_source.csv.
/// </summary>
public static class EpisodeCommentsCsvParser
{
    public static List<EpisodeCommentRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<EpisodeCommentRecord>().ToList();
    }
}
