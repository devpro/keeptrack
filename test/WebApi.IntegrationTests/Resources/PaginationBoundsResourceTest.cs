using System.Net;
using System.Threading.Tasks;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// <c>PagedRequest.Page</c>/<c>PageSize</c> carried no validation, so an out-of-range value reached the
/// repository unchecked (see AGENTS.md's "No pagination bounds" finding).
/// A negative <c>Page</c> produces a negative Mongo <c>Skip</c>, which the driver rejects with an unhandled
/// exception the caller sees as a bare 500.
/// A zero <c>PageSize</c> produces <c>Limit(0)</c>, which the Mongo C# driver treats as "no limit" rather
/// than "no results" - the opposite of what the parameter name promises.
/// <para>
/// <c>PageSize</c> deliberately keeps no upper bound: a first version of this fix capped it at 100 and broke
/// real production traffic (<c>CarDetail</c>/<c>HealthProfileDetail</c>/<c>HouseDetail</c> request
/// <c>pageSize=int.MaxValue</c> to fetch a single parent's whole child collection in one page, see
/// <c>PagedRequest.PageSize</c>'s own remarks), so <see cref="Get_WithAVeryLargePageSize_IsStillOk"/> guards
/// that regression rather than re-capping it.
/// </para>
/// <para>
/// Movies stand in for the whole base class, same convention as <see cref="MalformedIdResourceTest"/>: the
/// binding and validation is identical for every controller extending <c>DataCrudControllerBase</c>.
/// </para>
/// </summary>
public class PaginationBoundsResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task Get_WithNegativePage_Answers400()
    {
        await Authenticate();

        await GetAsync("/api/movies?page=-1", HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Get_WithZeroPage_Answers400()
    {
        await Authenticate();

        await GetAsync("/api/movies?page=0", HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Get_WithZeroPageSize_Answers400()
    {
        await Authenticate();

        await GetAsync("/api/movies?pageSize=0", HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Get_WithAVeryLargePageSize_IsStillOk()
    {
        await Authenticate();

        await GetAsync($"/api/movies?pageSize={int.MaxValue}", HttpStatusCode.OK);
    }

    [Fact]
    public async Task Get_WithAnOrdinaryPageAndPageSize_IsOk()
    {
        await Authenticate();

        await GetAsync("/api/movies?page=1&pageSize=20", HttpStatusCode.OK);
    }
}
