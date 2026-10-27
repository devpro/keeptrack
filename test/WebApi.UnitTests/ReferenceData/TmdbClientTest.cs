using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// TMDB's <c>/changes</c> with only a <c>start_date</c> answers the changes of that one day, not the changes since it, and rejects a range over 14 days.
/// A check that ignored either missed every season aired after the day a reference was last enriched, so the sync never fetched it.
/// </summary>
[Trait("Category", "UnitTests")]
public class TmdbClientTest
{
    private static TmdbClient BuildClient(StubHttpMessageHandler handler) =>
        new(new HttpClient(handler) { BaseAddress = new Uri("https://api.themoviedb.org/3/") }, new TmdbSettings { ApiKey = "k" });

    private sealed class StubHttpMessageHandler(string body) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    [Fact]
    public async Task HasTvShowChangedSinceAsync_AsksForTheWholeRangeUpToToday()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[{"key":"season","items":[]}]}""");
        var since = DateTime.UtcNow.AddDays(-3);

        var changed = await BuildClient(handler).HasTvShowChangedSinceAsync("203857", since, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        handler.Requests.Should().ContainSingle();
        var query = handler.Requests[0].Query;
        query.Should().Contain($"start_date={since:yyyy-MM-dd}");
        query.Should().Contain($"end_date={DateTime.UtcNow:yyyy-MM-dd}");
    }

    [Fact]
    public async Task HasTvShowChangedSinceAsync_ReportsNoChange_WhenTheRangeHasNone()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[]}""");

        var changed = await BuildClient(handler).HasTvShowChangedSinceAsync("203857", DateTime.UtcNow.AddDays(-3), TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
    }

    [Fact]
    public async Task HasTvShowChangedSinceAsync_ReportsAChangeWithoutCalling_WhenTheRangeExceedsWhatTmdbAccepts()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[]}""");

        var changed = await BuildClient(handler).HasTvShowChangedSinceAsync("203857", DateTime.UtcNow.AddDays(-30), TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        handler.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task HasTvShowChangedSinceAsync_StillAsksTmdb_AtExactlyTheLongestRangeItAccepts()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[]}""");
        var since = DateTime.UtcNow.AddDays(-14);

        var changed = await BuildClient(handler).HasTvShowChangedSinceAsync("203857", since, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        handler.Requests.Should().ContainSingle().Which.Query.Should().Contain($"start_date={since:yyyy-MM-dd}");
    }

    [Fact]
    public async Task HasTvShowChangedSinceAsync_ReportsAChangeWithoutCalling_OneDayPastTheLongestRange()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[]}""");

        var changed = await BuildClient(handler).HasTvShowChangedSinceAsync("203857", DateTime.UtcNow.AddDays(-15), TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        handler.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task HasMovieChangedSinceAsync_AsksForTheWholeRangeUpToToday()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[{"key":"images","items":[]}]}""");
        var since = DateTime.UtcNow.AddDays(-3);

        var changed = await BuildClient(handler).HasMovieChangedSinceAsync("603", since, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        var request = handler.Requests.Should().ContainSingle().Subject;
        request.AbsolutePath.Should().EndWith("/movie/603/changes");
        request.Query.Should().Contain($"start_date={since:yyyy-MM-dd}").And.Contain($"end_date={DateTime.UtcNow:yyyy-MM-dd}");
    }

    [Fact]
    public async Task HasMovieChangedSinceAsync_ReportsAChangeWithoutCalling_WhenTheRangeExceedsWhatTmdbAccepts()
    {
        var handler = new StubHttpMessageHandler("""{"changes":[]}""");

        var changed = await BuildClient(handler).HasMovieChangedSinceAsync("603", DateTime.UtcNow.AddDays(-30), TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        handler.Requests.Should().BeEmpty();
    }
}
