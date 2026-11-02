using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

[CsvRecord]
public partial class ShowCommentRecord
{
    [CsvColumn("tv_show_id")]
    public required string TvShowId { get; set; }

    [CsvColumn("comment")]
    public required string Comment { get; set; }

    [CsvColumn("created_at")]
    public required DateTime CreatedAt { get; set; }
}

/// <summary>
/// Parses TV Time's show_comment.csv: the exporting user's own free-text comments on shows.
/// The export only holds the requesting user's rows, so nothing is filtered by user.
/// </summary>
public static class ShowCommentsCsvParser
{
    public static List<ShowCommentRecord> Parse(Stream csvStream)
    {
        return ImportCsv.ReadRecords<ShowCommentRecord>(csvStream);
    }
}
