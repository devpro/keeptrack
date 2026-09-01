using System;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Covers the account-management page - previously the only walkthrough with no test at any level -
/// and, with it, the user-preferences UI: the signed-in identity renders, and toggling a preference checkbox round-trips through the real UI
/// (toggle → persisted → a fresh page load reflects it). The preference is restored to its original value via the API so the shared test account is left unchanged.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class ManageAccountSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    private const string PreferencesUrl = "api/user-preferences";

    [Fact]
    public async Task ManagePage_ShowsIdentity_AndPersistsAPreferenceToggle()
    {
        SkipIfReadOnly();

        var manage = await new ManageAccountPage(Page).OpenAsync();
        await Assertions.Expect(manage.SignedInAs).ToBeVisibleAsync();

        var pref = manage.ChasseAuxLivresPreference;
        await Assertions.Expect(pref).ToBeVisibleAsync();
        var original = await GetChasseAuxLivresAsync();

        try
        {
            await ToggleUntilPersistedAsync(pref, original);

            // A fresh page load reflecting the persisted value is the actual UI round-trip assertion.
            await manage.OpenAsync();
            await Assertions.Expect(manage.ChasseAuxLivresPreference).ToBeCheckedAsync(new LocatorAssertionsToBeCheckedOptions { Checked = !original });
        }
        finally
        {
            var ct = TestContext.Current.CancellationToken;
            var prefs = await Fixture.ApiHttpClient.GetFromJsonAsync<UserPreferencesDto>(PreferencesUrl, ct) ?? new UserPreferencesDto();
            prefs.Features.ShowChasseAuxLivresLink = original;
            await Fixture.ApiHttpClient.PutAsJsonAsync(PreferencesUrl, prefs, ct);
        }
    }

    /// <summary>
    /// Toggles the preference checkbox through the prerender→interactive gap: the very first <c>@onchange</c> after a fresh load can land
    /// before the Blazor circuit is live (the same gap <see cref="PageBase.ClickUntilAsync"/> mitigates for buttons), so re-click until the
    /// change actually reaches the server - detected as the stored value flipping away from its original value. The first click that registers
    /// server-side flips it to <c>!original</c>, so extra pre-connection DOM-only flips don't affect the final persisted value.
    /// </summary>
    private async Task ToggleUntilPersistedAsync(ILocator pref, bool original, int maxAttempts = 8)
    {
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            await pref.ClickAsync();

            for (var poll = 0; poll < 8; poll++)
            {
                if (await GetChasseAuxLivresAsync() != original)
                {
                    return;
                }

                await Task.Delay(200);
            }
        }

        throw new TimeoutException("The preference toggle never reached the server.");
    }

    private async Task<bool> GetChasseAuxLivresAsync()
    {
        var prefs = await Fixture.ApiHttpClient.GetFromJsonAsync<UserPreferencesDto>(PreferencesUrl);
        return prefs?.Features.ShowChasseAuxLivresLink ?? false;
    }
}
