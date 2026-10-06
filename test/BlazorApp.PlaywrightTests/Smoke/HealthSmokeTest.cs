using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Walks the health journal end to end: create a profile, add an appointment through the modal (a price, no reimbursement), and check the balance surfaces as the row's "to check" badge.
/// The journal table is the only warning surface, with no summary panel above it.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class HealthSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddProfileAndUnbalancedAppointment_ThenDelete()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke Health {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenHealthAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        var detail = new HealthProfileDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/health-profiles");
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(name);

        // Cover image: a health profile keeps the default portrait shape (a person's photo, unlike the "wide" car, house, collectible and gear), so only the detail banner round trip.
        const string imageUrl = "https://picsum.photos/seed/e2e-health/300/400";
        await DetailPageBase.SetFieldAsync(detail.ImageUrlInput, imageUrl);
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", imageUrl);

        // an appointment paid 60 with nothing reimbursed yet comes back flagged
        await AddEntryAsync();
        // data-testid, not GetByLabel, since the modal's label and input pairs have no for/id association (see docs/testing.md's end-to-end section)
        await Page.GetByTestId("practitioner-input").FillAsync("Dr E2e");
        await Page.GetByTestId("price-input").FillAsync("60");
        await SaveModalAsync();

        // the bare warning sign in the row is the whole warning surface
        await Assertions.Expect(Page.GetByText("⚠").First).ToBeVisibleAsync();
        await Assertions.Expect(Page.GetByText("Dr E2e").First).ToBeVisibleAsync();

        list = await detail.OpenHealthAsync();
        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }

    /// <summary>
    /// Takes a specialty and a practitioner from their suggestion dropdowns rather than typing them out, each way a user can: clicking an item, and pressing Enter on the match typing highlighted by itself.
    /// It also pins the rule keeping that automatic highlight safe: Tab leaves a half-typed value alone.
    /// A test that only fills the input, like the one above, exercises a plain text field and proves nothing about the dropdown.
    /// It would miss a click on a suggestion doing nothing, the click blurring the input and the focusout handler tearing the menu down before Blazor dispatches the click.
    /// </summary>
    [Fact]
    public async Task PickSpecialtyAndPractitionerFromTheSuggestionDropdown()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke Health {Guid.NewGuid():N}";
        // guid-bearing values, so the prefixes typed below narrow each menu to this run's single entry
        var specialty = $"E2eSpecialty{Guid.NewGuid():N}";
        var practitioner = $"Dr E2eSuggest {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenHealthAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        var detail = new HealthProfileDetailPage(Page);
        await detail.WaitForReadyAsync();
        // Registered once the item exists, so an assertion failure below still removes it, and the profile cascades to its journal entries.
        TrackOpenItem("/api/health-profiles");

        // a first entry, typed in full: this is what puts both values in *this account's* suggestion lists
        await AddEntryAsync();
        await Page.GetByTestId("specialty-input").FillAsync(specialty);
        await Page.GetByTestId("practitioner-input").FillAsync(practitioner);
        await SaveModalAsync();
        await Assertions.Expect(JournalCell(specialty)).ToHaveCountAsync(1);

        // a second entry with the same two values, this time taken from the dropdown.
        // The form re-fetches its suggestions every time the modal opens, so the entry above is already on offer.
        await AddEntryAsync();

        // Tab is a navigation key and leaves a half-typed value alone, however good the highlighted match, or a new value would be rewritten into an existing one containing it.
        var specialtyInput = Page.GetByTestId("specialty-input");
        var specialtyPrefix = specialty[..20];
        await specialtyInput.FillAsync(specialtyPrefix);
        await specialtyInput.PressAsync("Tab");
        await Assertions.Expect(specialtyInput).ToHaveValueAsync(specialtyPrefix);

        // by click
        await specialtyInput.FillAsync(specialtyPrefix);
        await Menu.GetByText(specialty, new LocatorGetByTextOptions { Exact = true }).ClickAsync();
        await Assertions.Expect(specialtyInput).ToHaveValueAsync(specialty);

        // by keyboard, and with no ↓ first: typing highlights the match on its own, Enter takes it
        var practitionerInput = Page.GetByTestId("practitioner-input");
        await practitionerInput.FillAsync(practitioner[..22]);
        await practitionerInput.PressAsync("Enter");
        await Assertions.Expect(practitionerInput).ToHaveValueAsync(practitioner);

        // and what the dropdown filled in reaches the journal, both rows carrying both values
        await SaveModalAsync();
        await Assertions.Expect(JournalCell(specialty)).ToHaveCountAsync(2);
        await Assertions.Expect(JournalCell(practitioner)).ToHaveCountAsync(2);

        list = await detail.OpenHealthAsync();
        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }

    /// <summary>The open suggestion dropdown, scoped, since a value saved in the journal below renders the same text as the menu item offering it.</summary>
    private ILocator Menu => Page.Locator(".kt-autocomplete-menu");

    /// <summary>
    /// Journal cells holding exactly this text.
    /// Counting page-wide text instead would double-count a specialty: the "Last seen" list above the journal renders it too (as a &lt;span&gt;, not a cell), once per distinct specialty rather than once per entry.
    /// </summary>
    private ILocator JournalCell(string text) =>
        Page.GetByRole(AriaRole.Cell, new PageGetByRoleOptions { Name = text, Exact = true });

    private Task AddEntryAsync() =>
        Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add entry" }).ClickAsync();

    private Task SaveModalAsync() =>
        Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Save" }).ClickAsync();
}
