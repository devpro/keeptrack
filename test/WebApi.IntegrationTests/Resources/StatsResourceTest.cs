using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Covers the Home page's collection-overview endpoint - and, through it, the shared
/// <c>MongoDbRepositoryBase.CountAsync</c> every repository inherits.
/// </summary>
public class StatsResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/stats";

    [Fact]
    public async Task Stats_RequireAuthentication()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Stats_CountTheCallersItems()
    {
        await Authenticate();

        var book = await PostAsync<BookDto>("/api/books", new Faker<BookDto>()
            .Rules((f, o) => { o.Title = f.Random.AlphaNumeric(14); o.Author = f.Random.AlphaNumeric(8); })
            .Generate());
        var movie = await PostAsync<MovieDto>("/api/movies", new Faker<MovieDto>()
            .Rules((f, o) => { o.Title = f.Random.AlphaNumeric(14); })
            .Generate());

        try
        {
            var stats = await GetAsync<CollectionStatsDto>($"/{ResourceEndpoint}");

            // the shared test tenant may hold other tests' in-flight items, so lower bounds only
            stats.Books.Should().BeGreaterThanOrEqualTo(1);
            stats.Movies.Should().BeGreaterThanOrEqualTo(1);
        }
        finally
        {
            await DeleteAsync($"/api/books/{book.Id}");
            await DeleteAsync($"/api/movies/{movie.Id}");
        }
    }
}
