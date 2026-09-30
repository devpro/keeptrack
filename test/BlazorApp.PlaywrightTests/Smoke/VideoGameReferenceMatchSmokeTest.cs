using System;
using System.Collections.Generic;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.WebApi.Contracts.Dto;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// The reference-matching journey a person actually walks for a video game, driven through the real UI against the real IGDB.
/// </summary>
/// <remarks>
/// <para>
/// Every other test in this area feeds candidates straight into the matching rule, which is why a run of regressions reached the owner unnoticed: the rule was right each time and the journey around it was not.
/// A title typed without its colon never reaches the provider's exact-name query, an item created before its year is known writes no reference at all, and editing a title afterwards has to be able to both re-point and clear a link.
/// None of that is visible from a unit test.
/// </para>
/// <para>
/// Two rules are being pinned here, both the owner's.
/// A year is required for any automatic link, because video game catalogues are full of same-titled works and a title alone identifies nothing.
/// And editing a field never searches by itself: the user clicks "check for reference match", and that is the only thing that re-resolves.
/// </para>
/// <para>
/// "Code Vein" is chosen because IGDB spells its family in ways that exercise all of this from one starting point: exactly one game is named "Code Vein" (28168, 2019), "Code Vein: Season Pass" (131955, 2019) matches only once punctuation is folded, and "code vein season" matches nothing at all.
/// </para>
/// </remarks>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class VideoGameReferenceMatchSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    private const string BaseTitle = "Code Vein";
    private const string SeasonPassTitle = "code vein season pass";
    private const string UnmatchableTitle = "code vein season";
    private const string Year = "2019";

    /// <summary>
    /// Scenario 1: a linked game whose title is edited to name a different real game re-points at that game's reference.
    /// </summary>
    [Fact]
    public async Task EditingTheTitleToAnotherRealGame_RepointsTheReference_WhenTheUserChecksAgain()
    {
        SkipIfReadOnly();
        var (detail, id) = await CreateGameAsync(BaseTitle, Year);

        var original = await WaitForReferenceLinkAsync(id);
        original.Should().NotBeNullOrEmpty("IGDB holds exactly one game named \"Code Vein\" (2019)");

        // The step that was claimed in prose and never tested: editing a field must not search by itself, and must not disturb the link either.
        // Waits for the edit to actually reach the server rather than sleeping, so the assertion is made at a known point instead of a hoped-for one.
        await DetailPageBase.SetFieldAsync(detail.TitleInput, SeasonPassTitle);
        var afterEdit = await WaitForTitleAsync(id, SeasonPassTitle);

        afterEdit.ReferenceId.Should().Be(original, "editing a title changes nothing until the user asks; the button is the only thing that re-resolves");

        await detail.ClickCheckReferenceMatchAsync();

        var repointed = await WaitForReferenceLinkAsync(id, original);
        repointed.Should().NotBeNullOrEmpty("\"code vein season pass\" is IGDB's \"Code Vein: Season Pass\" (2019) once punctuation is folded");
        repointed.Should().NotBe(original, "it is a different game, so it is a different reference document");
    }

    /// <summary>
    /// Scenario 2: a linked game whose title is edited to something no game is called loses its link rather than keeping a stale one.
    /// </summary>
    /// <remarks>
    /// Clearing is the important half.
    /// A link that survives the title it was based on is worse than no link: it renders a cover and a rating for a different work, and nothing about the item says so.
    /// </remarks>
    [Fact]
    public async Task EditingTheTitleToSomethingNoGameIsCalled_ClearsTheReference_WhenTheUserChecksAgain()
    {
        SkipIfReadOnly();
        var (detail, id) = await CreateGameAsync(BaseTitle, Year);

        var original = await WaitForReferenceLinkAsync(id);
        original.Should().NotBeNullOrEmpty();

        await DetailPageBase.SetFieldAsync(detail.TitleInput, UnmatchableTitle);
        await detail.ClickCheckReferenceMatchAsync();

        var after = await WaitForReferenceLinkAsync(id, original);
        after.Should().BeNullOrEmpty("no game is named \"code vein season\", and a link outliving its title points at the wrong work");
    }

    /// <summary>
    /// Scenario 3: a game created without a year is left alone, and links as soon as the year is supplied and checked.
    /// </summary>
    /// <remarks>
    /// The first half is the owner's rule that a year is required, and it holds even here where the provider has exactly one game by that name.
    /// The second half is what makes the rule liveable: the year is not a one-shot chance taken at creation, it can be supplied later and the same match then happens.
    /// </remarks>
    [Fact]
    public async Task CreatingWithoutAYear_LinksNothingUntilTheYearIsSuppliedAndChecked()
    {
        SkipIfReadOnly();
        var (detail, id) = await CreateGameAsync(BaseTitle, year: null);

        // Asserted immediately, with nothing waited for, and that is sound rather than lucky: without a year the server returns from resolution before it asks any provider anything, so no later moment can produce a different answer.
        var beforeYear = await ReadReferenceIdAsync(id);
        beforeYear.Should().BeNullOrEmpty("a title alone identifies nothing in this domain, so nothing may be linked without a year");

        await DetailPageBase.SetFieldAsync(detail.YearInput, Year);
        await detail.ClickCheckReferenceMatchAsync();

        var afterYear = await WaitForReferenceLinkAsync(id);
        afterYear.Should().NotBeNullOrEmpty("\"Code Vein\" (2019) is exactly one game on IGDB");
    }

    /// <summary>
    /// Adds a game through the list's own Add form and opens its detail page, registering it for deletion as soon as it exists.
    /// </summary>
    private async Task<(VideoGameDetailPage Detail, string Id)> CreateGameAsync(string title, string? year)
    {
        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenVideoGamesAsync();
        await list.ClickAddAsync();
        await list.FillByPlaceholderAsync("Title", title);
        if (year is not null)
        {
            await list.FillByPlaceholderAsync("Year", year);
        }

        await list.SaveNewAsync();

        var detail = new VideoGameDetailPage(Page);
        await detail.WaitForReadyAsync();
        TrackOpenItem("/api/video-games");
        return (detail, ExtractIdFromUrl(Page.Url));
    }

    /// <summary>
    /// Waits for the item's reference link to settle, optionally until it differs from <paramref name="previous"/>.
    /// </summary>
    /// <remarks>
    /// Resolution on create runs as a detached background task and the check button's own resolve propagates by title and year rather than by id, so neither is observable the instant the UI returns.
    /// Returning the value rather than asserting keeps "it never linked" a real answer the caller can assert on, instead of a timeout that hides which half of the journey failed.
    /// </remarks>
    private async Task<string?> WaitForReferenceLinkAsync(string id, string? previous = null)
    {
        for (var attempt = 0; attempt < 150; attempt++)
        {
            var referenceId = await ReadReferenceIdAsync(id);
            var settled = previous is null ? !string.IsNullOrEmpty(referenceId) : referenceId != previous;
            if (settled)
            {
                return referenceId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
        }

        return previous is null ? null : await ReadReferenceIdAsync(id);
    }

    /// <summary>
    /// Waits until the item the server holds carries <paramref name="expected"/> as its title, and returns it.
    /// </summary>
    /// <remarks>
    /// The signal that a detail-page edit has been processed, for asserting what must <i>not</i> have changed alongside it.
    /// A negative has nothing of its own to wait for, so waiting on the edit itself is what turns "assert after a guessed delay" into "assert at a known point".
    /// </remarks>
    private async Task<VideoGameDto> WaitForTitleAsync(string id, string expected)
    {
        VideoGameDto? game = null;
        for (var attempt = 0; attempt < 30 && !string.Equals(game?.Title, expected, StringComparison.Ordinal); attempt++)
        {
            if (attempt > 0)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
            }

            game = await Fixture.ApiHttpClient.GetFromJsonAsync<VideoGameDto>($"/api/video-games/{id}", TestContext.Current.CancellationToken);
        }

        game!.Title.Should().Be(expected, "the title edit never reached the server, so nothing after this point would mean anything");
        return game;
    }

    /// <summary>
    /// Reads the item's current reference link, remembering every reference it has ever pointed at so the run can leave the database as it found it.
    /// </summary>
    /// <remarks>
    /// Every reference these tests cause to be created has to go, and the currently-linked one is not enough: scenario 1 deliberately moves the item from one reference to another, so unlinking at the end would leave the first behind.
    /// See <see cref="End2EndFixture.RemoveVideoGameReferencesAsync"/> for why a leftover is not merely untidy here but turns these tests green and meaningless.
    /// </remarks>
    private async Task<string?> ReadReferenceIdAsync(string id)
    {
        var game = await Fixture.ApiHttpClient.GetFromJsonAsync<VideoGameDto>($"/api/video-games/{id}", TestContext.Current.CancellationToken);
        if (!string.IsNullOrEmpty(game?.ReferenceId) && _seenReferenceIds.Add(game.ReferenceId))
        {
            TrackCleanup(() => Fixture.RemoveVideoGameReferencesAsync([game.ReferenceId]));
        }

        return game?.ReferenceId;
    }

    private readonly HashSet<string> _seenReferenceIds = [];
}
