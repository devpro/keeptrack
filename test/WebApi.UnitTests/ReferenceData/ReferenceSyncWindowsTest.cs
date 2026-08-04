using System;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The admin's "sync now" and the periodic background pass run the same code and differ only in these
/// windows, so an unforced "sync now" must resolve to the very same values the background tick uses - the
/// one property that would break silently (both callers keep working, they just stop agreeing on what
/// "stale" means).
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
    /// Pins the documented cadence: reference documents are re-checked far more often than the discovery
    /// rankings, which barely move week to week.
    /// </summary>
    [Fact]
    public void Periodic_ChecksReferencesEveryThreeDaysAndExploreRankingsEverySeven()
    {
        ReferenceSyncWindows.Periodic.References.Should().Be(TimeSpan.FromDays(3));
        ReferenceSyncWindows.Periodic.Explore.Should().Be(TimeSpan.FromDays(7));
    }
}
