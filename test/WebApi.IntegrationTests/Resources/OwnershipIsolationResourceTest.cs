using System;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Every action on <c>DataCrudControllerBase</c> scopes its Mongo query by the caller's own owner id, but
/// nothing had ever proven it end to end.
/// <para>
/// A mocked-repository unit test cannot prove a Mongo filter (see AGENTS.md's quality bar), and every other
/// HTTP test signs in as the one Firebase test account, so there was never a second owner's document to try
/// to reach through it.
/// Movies stand in for the whole base class here, the same convention <see cref="MalformedIdResourceTest"/>
/// uses: the scoping is identical across all twenty repositories.
/// The other owner's document is seeded directly through the repository, since HTTP has no way to
/// authenticate as a second account, and is cleaned up the same raw way.
/// </para>
/// </summary>
public class OwnershipIsolationResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task AnotherOwnersRecord_IsInvisibleAndUnreachable_ThroughEveryCrudAction()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();

        var otherOwnerId = $"other-owner-{Guid.NewGuid():N}";
        const string originalTitle = "Not yours to see";
        var otherOwnersMovie = await repository.CreateAsync(new()
        {
            OwnerId = otherOwnerId,
            Title = originalTitle
        }, TestContext.Current.CancellationToken);
        TrackDocument("movie", otherOwnersMovie.Id);

        await Authenticate();

        // GetById must answer 404, not the data.
        await GetAsync($"/api/movies/{otherOwnersMovie.Id}", HttpStatusCode.NotFound);

        // The list must never include another owner's document.
        var page = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(originalTitle)}");
        page.Items.Should().NotContain(m => m.Id == otherOwnersMovie.Id);

        // Put answers 204 either way (see MalformedIdResourceTest), so the proof is that the record itself
        // never changes.
        await PutAsync($"/api/movies/{otherOwnersMovie.Id}", new MovieDto { Id = otherOwnersMovie.Id, Title = "Overwritten" });
        var untouched = await repository.FindOneAsync(otherOwnersMovie.Id!, otherOwnerId, TestContext.Current.CancellationToken);
        untouched.Should().NotBeNull();
        untouched!.Title.Should().Be(originalTitle);

        // Same for Delete: 204, but the document must still be there afterwards.
        await DeleteAsync($"/api/movies/{otherOwnersMovie.Id}");
        var stillThere = await repository.FindOneAsync(otherOwnersMovie.Id!, otherOwnerId, TestContext.Current.CancellationToken);
        stillThere.Should().NotBeNull();
    }
}
