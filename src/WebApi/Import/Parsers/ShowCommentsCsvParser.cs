using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class ShowCommentRecord
{
    [Name("tv_show_id")]
    public required string TvShowId { get; set; }

    [Name("comment")]
    public required string Comment { get; set; }

    [Name("created_at")]
    public required DateTime CreatedAt { get; set; }
}

/// <summary>
/// Parses TV Time's show_comment.csv: the exporting user's own free-text comments on shows.
/// The GDPR export only ever contains the requesting user's own rows, so no user-id filtering is needed.
/// </summary>
public static class ShowCommentsCsvParser
{
    public static List<ShowCommentRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<ShowCommentRecord>().ToList();
    }
}
