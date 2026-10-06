using System.Net;
using System.Threading.Tasks;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// <c>PagedRequest.Page</c> and <c>PageSize</c> are validated on model binding, before reaching the repository.
/// A negative <c>Page</c> would produce a negative Mongo <c>Skip</c>, which the driver rejects with an unhandled exception, a bare 500.
/// A zero <c>PageSize</c> would produce <c>Limit(0)</c>, which the Mongo C# driver treats as "no limit" rather than "no results".
/// <para>
/// <c>PageSize</c> keeps no upper bound (see the backlog), since the journal pages request <c>pageSize=int.MaxValue</c> to fetch a parent's whole child collection in one page (see <c>PagedRequest.PageSize</c>).
/// <see cref="Get_WithAVeryLargePageSize_IsStillOk"/> guards that.
/// </para>
/// <para>
/// Movies stand in for the whole base class, same convention as <see cref="MalformedIdResourceTest"/>: the binding and validation is identical for every controller extending <c>DataCrudControllerBase</c>.
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
