using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using MongoDB.Bson;
using MongoDB.Driver;
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

        preferences.Features.ShowChasseAuxLivresLink.Should().BeFalse();
    }

    [Fact]
    public async Task Put_ThenGet_RoundTripsTheSavedValue()
    {
        await Authenticate();
        // The document is created server-side under the caller's own owner id and has no id the test ever
        // sees, so it's cleaned up by owner. Leaving it behind would also quietly undermine
        // Get_ReturnsAllFalseDefaults_WhenNothingWasEverSaved above, whose whole point is the never-saved case.
        TrackDocumentsWhere("user_preference", Builders<BsonDocument>.Filter.Eq("owner_id", AuthenticatedUserId));

        await PutAsync($"/{ResourceEndpoint}", new UserPreferencesDto { Features = new UserPreferencesFeaturesDto { ShowChasseAuxLivresLink = true } });
        var afterFirstSave = await GetAsync<UserPreferencesDto>($"/{ResourceEndpoint}");
        afterFirstSave.Features.ShowChasseAuxLivresLink.Should().BeTrue();

        // a second PUT must update the same document (upsert by owner_id), not collide with the unique index
        await PutAsync($"/{ResourceEndpoint}", new UserPreferencesDto { Features = new UserPreferencesFeaturesDto { ShowChasseAuxLivresLink = false } });
        var afterSecondSave = await GetAsync<UserPreferencesDto>($"/{ResourceEndpoint}");
        afterSecondSave.Features.ShowChasseAuxLivresLink.Should().BeFalse();
    }
}
