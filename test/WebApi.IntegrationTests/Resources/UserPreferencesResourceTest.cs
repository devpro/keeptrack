using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Covers the singleton-per-owner preferences resource: the "nothing saved yet" default, and the
/// upsert-by-owner-id persistence the repository relies on (a first PUT inserts, a later one updates the
/// same document rather than colliding with the unique owner_id index).
/// </summary>
public class UserPreferencesResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/user-preferences";

    [Fact]
    public async Task UserPreferences_RequireAuthentication()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Get_ReturnsAllFalseDefaults_WhenNothingWasEverSaved()
    {
        await Authenticate();

        var preferences = await GetAsync<UserPreferencesDto>($"/{ResourceEndpoint}");

        preferences.ShowChasseAuxLivresLink.Should().BeFalse();
    }

    [Fact]
    public async Task Put_ThenGet_RoundTripsTheSavedValue()
    {
        await Authenticate();

        await PutAsync($"/{ResourceEndpoint}", new UserPreferencesDto { ShowChasseAuxLivresLink = true });
        var afterFirstSave = await GetAsync<UserPreferencesDto>($"/{ResourceEndpoint}");
        afterFirstSave.ShowChasseAuxLivresLink.Should().BeTrue();

        // a second PUT must update the same document (upsert by owner_id), not collide with the unique index
        await PutAsync($"/{ResourceEndpoint}", new UserPreferencesDto { ShowChasseAuxLivresLink = false });
        var afterSecondSave = await GetAsync<UserPreferencesDto>($"/{ResourceEndpoint}");
        afterSecondSave.ShowChasseAuxLivresLink.Should().BeFalse();
    }
}
