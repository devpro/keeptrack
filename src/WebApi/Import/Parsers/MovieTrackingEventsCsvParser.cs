using CsvHelper;

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
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        csv.Read();
        csv.ReadHeader();

        var records = new List<MovieTrackingEventRecord>();
        while (csv.Read())
        {
            if (csv.GetField("entity_type") != "movie") continue;

            var eventType = csv.GetField("type") switch
            {
                "watch" => MovieTrackingEventType.Watched,
                "towatch" => MovieTrackingEventType.WantToWatch,
                "follow" => MovieTrackingEventType.Followed,
                _ => (MovieTrackingEventType?)null
            };
            if (eventType is null) continue;

            var movieName = csv.GetField("movie_name");
            if (string.IsNullOrEmpty(movieName)) continue;

            records.Add(new MovieTrackingEventRecord(movieName, eventType.Value, csv.GetField<DateTime>("created_at"), csv.GetField("uuid")));
        }

        return records;
    }
}
