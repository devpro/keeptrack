using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

[CsvRecord]
public partial class EpisodeCommentRecord
{
    [CsvColumn("tv_show_name")]
    public required string ShowTitle { get; set; }

    [CsvColumn("episode_season_number")]
    public required int SeasonNumber { get; set; }

    [CsvColumn("episode_number")]
    public required int EpisodeNumber { get; set; }

    [CsvColumn("comment")]
    public required string Comment { get; set; }

    [CsvColumn("created_at")]
    public required DateTime CreatedAt { get; set; }
}

/// <summary>
/// Parses TV Time's episode_comment.csv: the exporting user's own free-text comments on episodes.
/// Episodes are identified by show name only, with no show id, as in seen_episode_source.csv.
/// </summary>
public static class EpisodeCommentsCsvParser
{
    public static List<EpisodeCommentRecord> Parse(Stream csvStream)
    {
        return ImportCsv.ReadRecords<EpisodeCommentRecord>(csvStream);
    }
}
