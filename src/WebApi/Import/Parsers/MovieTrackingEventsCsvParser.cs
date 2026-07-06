using System;
using System.Collections.Generic;
using System.IO;
using CsvHelper;

namespace Keeptrack.WebApi.Import.Parsers;

public enum MovieTrackingEventType
{
    Watched,
    WantToWatch,
    Followed
}

public sealed record MovieTrackingEventRecord(string MovieName, MovieTrackingEventType EventType, DateTime CreatedAt);

/// <summary>
/// Parses the movie-related rows of tracking-prod-records.csv (tracking-prod-records-v2.csv, TV Time's
/// newer-generation log, carries no movie data at all - confirmed against a real export). Movies have
/// no dedicated "watched"/"want to watch" file the way shows do (followed_tv_show.csv,
/// user_show_special_status.csv); this generic event log turns out to be the only source for both, via
/// entity_type "movie" rows of type "watch"/"towatch"/"follow" - each individually dated. Previously
/// assumed unrecoverable ("import movies without a watch date"); found by grepping the real export for
/// a movie-watch signal instead of accepting that as final, the same way the episode-history gaps were found.
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

            records.Add(new MovieTrackingEventRecord(movieName, eventType.Value, csv.GetField<DateTime>("created_at")));
        }

        return records;
    }
}
