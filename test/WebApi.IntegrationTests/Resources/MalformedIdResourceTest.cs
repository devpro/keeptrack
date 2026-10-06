using System.Net;
using System.Threading.Tasks;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// An id that isn't a 24-digit hex string can't name a document, and is answered like any other id naming nothing rather than failing.
/// <para>
/// This is MongoDB serialization semantics, so only a real-MongoDB test proves it.
/// Every entity behind <c>MongoDbRepositoryBase</c> maps <c>_id</c> as an ObjectId,
/// so the driver runs an id filter's string through <c>ObjectId.Parse</c>, which throws <see cref="System.FormatException"/>.
/// <c>ApiExceptionFilterAttribute</c> would turn it into a 500, and the Blazor app into its error page, for a hand-edited, truncated or stale URL.
/// </para>
/// Movies stand in for the whole base class (all twenty repositories share these methods),
/// and TV shows are tested separately, since their delete also runs the cascade hook on the same raw route id.
/// </summary>
public class MalformedIdResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string MalformedId = "not-an-object-id";

    /// <summary>Well-formed and parseable, but vanishingly unlikely to have been minted, the "absent" control.</summary>
    private const string AbsentButWellFormedId = "0123456789abcdef01234567";

    [Theory]
    [InlineData(MalformedId)]
    [InlineData(AbsentButWellFormedId)]
    public async Task GetById_Answers404_ForAnIdThatNamesNothing(string id)
    {
        await Authenticate();

        await GetAsync($"/api/movies/{id}", HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData(MalformedId)]
    [InlineData(AbsentButWellFormedId)]
    public async Task Delete_IsANoOp_ForAnIdThatNamesNothing(string id)
    {
        await Authenticate();

        await DeleteAsync($"/api/movies/{id}");
    }

    /// <summary>
    /// The cascade hook (<c>OnDeletedAsync</c>) runs on the raw route id whether or not the parent delete matched,
    /// so it reaches the child collection's parent-id filter, an ObjectId field too, even for an id with nothing to remove.
    /// </summary>
    [Theory]
    [InlineData(MalformedId)]
    [InlineData(AbsentButWellFormedId)]
    public async Task DeleteOfACascadingParent_IsANoOp_ForAnIdThatNamesNothing(string id)
    {
        await Authenticate();

        await DeleteAsync($"/api/tv-shows/{id}");
    }

    [Theory]
    [InlineData(MalformedId)]
    [InlineData(AbsentButWellFormedId)]
    public async Task Put_IsANoOp_ForAnIdThatNamesNothing(string id)
    {
        await Authenticate();

        await PutAsync($"/api/movies/{id}", new MovieDto { Id = id, Title = "Never stored" });
    }
}
