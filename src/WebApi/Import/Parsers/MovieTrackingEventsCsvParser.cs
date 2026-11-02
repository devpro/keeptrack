using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

public enum MovieTrackingEventType
{
    Watched,
    WantToWatch,
    Followed
}

/// <summary>
/// A single movie event.
/// <paramref name="Uuid"/> is TV Time's tracking id per movie: every event (follow, watch, towatch) of one movie shares it,
/// and two movies sharing a title differ, so it is a stable key independent of the title.
/// </summary>
public sealed record MovieTrackingEventRecord(string MovieName, MovieTrackingEventType EventType, DateTime CreatedAt, string? Uuid);

/// <summary>
/// Parses the movie rows of tracking-prod-records.csv, since the newer tracking-prod-records-v2.csv carries no movie data.
/// Movies have no watched or want-to-watch file as shows do, and this event log is the only source of both: dated entity_type "movie" rows of type "watch", "towatch" or "follow".
/// </summary>
public static class MovieTrackingEventsCsvParser
{
    public static List<MovieTrackingEventRecord> Parse(Stream csvStream)
    {
        using var csv = ImportCsv.Open(csvStream);

        var records = new List<MovieTrackingEventRecord>();
        while (csv.Read())
        {
            if (csv.GetString("entity_type") != "movie") continue;

            var eventType = csv.GetString("type") switch
            {
                "watch" => MovieTrackingEventType.Watched,
                "towatch" => MovieTrackingEventType.WantToWatch,
                "follow" => MovieTrackingEventType.Followed,
                _ => (MovieTrackingEventType?)null
            };
            if (eventType is null) continue;

            var movieName = csv.GetString("movie_name");
            if (string.IsNullOrEmpty(movieName)) continue;

            records.Add(new MovieTrackingEventRecord(movieName, eventType.Value, csv.Parse<DateTime>("created_at"), csv.GetString("uuid")));
        }

        return records;
    }
}
