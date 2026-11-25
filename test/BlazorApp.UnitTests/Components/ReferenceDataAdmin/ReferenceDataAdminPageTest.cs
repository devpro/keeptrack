using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.ReferenceDataAdmin;
using Keeptrack.BlazorApp.UnitTests.Components.Shared;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.ReferenceDataAdmin;

/// <summary>The manual search of a reconciliation row: Enter asks the provider, any other key does not.</summary>
[Trait("Category", "UnitTests")]
public class ReferenceDataAdminPageTest
{
    private const string CandidatesPath = "/api/reference-data/provider-reconciliation/r1/candidates";

    private const string Placeholder = "Search IGDB with different text, or paste the game's page URL";

    private readonly StubApi _api = new StubApi()
        .Answer("/api/reference-data/providers", new List<ReferenceProviderDto>())
        .Answer("/api/reference-data/rating-sources", new List<RatingSourceOptionDto>())
        .Answer("/api/reference-data/explore-settings", new ExploreSettingsDto())
        .Answer("/api/reference-data/unresolved", new List<UnresolvedReferenceDto>())
        .Answer("/api/reference-data/provider-reconciliation", new ProviderReconciliationDto
        {
            Provider = "igdb",
            ProviderDisplayName = "IGDB",
            TotalReferences = 1,
            Gaps = [new ProviderGapDto { ReferenceId = "r1", Title = "Avengers" }]
        })
        .Answer("/api/system-status", new SystemStatusDto { InstanceName = "test", BookProvider = "googlebooks", VideoGameProvider = "igdb" })
        .Answer(CandidatesPath, new List<ReferenceSearchResultDto>());

    [Theory]
    [InlineData("Enter", 1)]
    [InlineData("a", 0)]
    public async Task OnlyEnter_AsksTheProvider(string key, int searches)
    {
        await using var page = await InteractiveRendering.RenderAsync<ReferenceDataAdminPage>(
            new Dictionary<string, object?>(),
            services => services.AddPageServices().AddSingleton(new ReferenceDataAdminApiClient(_api.CreateClient())));
        await page.ClickAsync("cursor:pointer");
        await page.RaiseAsync("oninput", new ChangeEventArgs { Value = "marvel" }, Placeholder);
        _api.Requests.Clear();

        await page.RaiseAsync("onkeydown", new KeyboardEventArgs { Key = key }, Placeholder);

        _api.Requests.Count(r => r.PathAndQuery.StartsWith(CandidatesPath) && r.PathAndQuery.Contains("marvel")).Should().Be(searches);
    }
}
