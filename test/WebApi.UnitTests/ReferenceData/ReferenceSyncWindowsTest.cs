using System;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The admin's "sync now" and the periodic pass run the same code and differ only by these windows, so an unforced "sync now" resolves to the background tick's values.
/// That would break silently, both callers working while disagreeing on what "stale" means.
/// </summary>
public class ReferenceSyncWindowsTest
{
    [Fact]
    public void For_WithoutForce_IsExactlyThePeriodicPassesWindows()
    {
        ReferenceSyncWindows.For(false).Should().Be(ReferenceSyncWindows.Periodic);
    }

    [Fact]
    public void For_WithForce_TakesEveryDocumentAndRanking()
    {
        var windows = ReferenceSyncWindows.For(true);

        windows.References.Should().Be(TimeSpan.Zero);
        windows.Explore.Should().Be(TimeSpan.Zero);
    }

    /// <summary>
    /// TMDB's change check only sees changes after the last enrichment, so forcing is the one way to recover a change it missed.
    /// </summary>
    [Fact]
    public void For_WithForce_FetchesInFull_WhereThePeriodicPassTrustsTheChangeCheck()
    {
        ReferenceSyncWindows.For(true).FullFetch.Should().BeTrue();
        ReferenceSyncWindows.Periodic.FullFetch.Should().BeFalse();
    }

    /// <summary>
    /// Pins the documented cadence: reference documents are re-checked far more often than the discovery rankings, which barely move week to week.
    /// </summary>
    [Fact]
    public void Periodic_ChecksReferencesEveryThreeDaysAndExploreRankingsEverySeven()
    {
        ReferenceSyncWindows.Periodic.References.Should().Be(TimeSpan.FromDays(3));
        ReferenceSyncWindows.Periodic.Explore.Should().Be(TimeSpan.FromDays(7));
    }
}
