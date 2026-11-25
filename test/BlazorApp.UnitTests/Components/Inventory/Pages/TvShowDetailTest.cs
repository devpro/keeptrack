using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory.Clients;
using Keeptrack.BlazorApp.Components.Inventory.Pages;
using Keeptrack.BlazorApp.Components.ReferenceData;
using Keeptrack.BlazorApp.UnitTests.Components.Shared;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Inventory.Pages;

/// <summary>The show page over a stubbed API: what it shows for each state of the data, and what each control saves.</summary>
[Trait("Category", "UnitTests")]
public class TvShowDetailTest
{
    private static readonly JsonSerializerOptions s_json = new(JsonSerializerDefaults.Web);

    private readonly StubApi _api = new();

    [Fact]
    public async Task AnUnknownShow_IsSaidNotFound()
    {
        await using var page = await OpenAsync();

        page.Shows("Show not found.").Should().BeTrue();
    }

    [Fact]
    public async Task ALinkedShow_ShowsItsReference_AndOnlyTheAiredEpisodes()
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire", ReferenceId = "r1" });
        _api.Answer("/api/reference-data/tv-shows/r1", new TvShowReferenceDto
        {
            Id = "r1",
            Title = "The Wire",
            Synopsis = "Baltimore.",
            Genres = ["Crime", "Drama"],
            Cast = [new CastMemberDto { Name = "Dominic West", CharacterName = "McNulty" }],
            Ratings = new Dictionary<string, ReferenceRatingDto> { ["tmdb"] = new() { Value = 8.6, Scale = 10 } },
            Episodes =
            [
                new ReferenceEpisodeDto { SeasonNumber = 1, EpisodeNumber = 1, Title = "The Target", AirDate = new DateOnly(2002, 6, 2) },
                new ReferenceEpisodeDto { SeasonNumber = 1, EpisodeNumber = 2, Title = "Unaired", AirDate = DateOnly.FromDateTime(DateTime.Today).AddYears(1) }
            ]
        });

        await using var page = await OpenAsync();

        foreach (var text in new[] { "Baltimore.", "Crime, Drama", "Cast", "Dominic West", "Reference rating", "Season 1", "The Target" })
        {
            page.Shows(text).Should().BeTrue(text);
        }

        page.Shows("Unaired").Should().BeFalse();
        page.Shows("Add episode watched").Should().BeFalse();
    }

    [Fact]
    public async Task AReferenceWithNothingInIt_ShowsNoEmptySection()
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire", ReferenceId = "r1" });
        _api.Answer("/api/reference-data/tv-shows/r1", new TvShowReferenceDto { Id = "r1", Title = "The Wire" });

        await using var page = await OpenAsync();

        page.Shows("No episode data available for this show yet.").Should().BeTrue();
        page.Shows("Cast").Should().BeFalse();
        page.Shows("Reference rating").Should().BeFalse();
    }

    [Fact]
    public async Task AnUnlinkedShow_OffersToAddAnEpisode()
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire" });

        await using var page = await OpenAsync();

        page.Shows("Add episode watched").Should().BeTrue();
    }

    [Fact]
    public async Task TheToggles_SaveTheirFlag()
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire" });
        await using var page = await OpenAsync();

        await page.ClickAsync("Favorites");
        LastSaved().IsFavorite.Should().BeTrue();

        await page.ClickAsync("btn btn-sm kt-toggle-btn ");
        LastSaved().IsWishlisted.Should().BeTrue();
        LastSaved().IsFavorite.Should().BeTrue();
    }

    [Theory]
    [InlineData("Current", TvShowStatus.Current, "btn btn-sm btn-warning")]
    [InlineData("Finished", TvShowStatus.Finished, "btn btn-sm btn-success")]
    [InlineData("Stopped", TvShowStatus.Stopped, "btn btn-sm btn-danger")]
    public async Task AStateButton_SetsItsState_AndClearsItWhenClickedAgain(string button, TvShowStatus state, string activeClass)
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire" });
        await using var page = await OpenAsync();

        await page.ClickAsync(button);
        LastSaved().State.Should().Be(state);
        page.TextsOf("class", activeClass).Should().Equal(button);

        await page.ClickAsync(button);
        LastSaved().State.Should().BeNull();
    }

    [Fact]
    public async Task TheFields_SaveWhatIsTyped()
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire", Year = 2001 });
        await using var page = await OpenAsync();

        await page.ChangeAsync("The Wire (US)", "kt-title-input");
        LastSaved().Title.Should().Be("The Wire (US)");
        await page.ChangeAsync("2002", "1970");
        LastSaved().Year.Should().Be(2002);
        await page.ChangeAsync("not a year", "1970");
        LastSaved().Year.Should().BeNull();
        await page.ChangeAsync("4.5", "5");
        LastSaved().Rating.Should().Be(4.5f);
        await page.ChangeAsync("Again", "3");
        LastSaved().Notes.Should().Be("Again");
    }

    [Fact]
    public async Task ABlankTitle_IsNotSaved()
    {
        Show(new TvShowDto { Id = "s1", Title = "The Wire" });
        await using var page = await OpenAsync();

        await page.ChangeAsync(" ", "kt-title-input");

        _api.Requests.Should().NotContain(r => r.Method == "PUT");
    }

    private void Show(TvShowDto show) => _api
        .Answer("/api/tv-shows/s1", show)
        .Answer("/api/episodes", new PagedResult<EpisodeDto>([], 0, 1, 5000));

    private TvShowDto LastSaved() => JsonSerializer.Deserialize<TvShowDto>(_api.Requests.Last(r => r.Method == "PUT").Body!, s_json)!;

    private Task<InteractiveRendering> OpenAsync() => InteractiveRendering.RenderAsync<TvShowDetail>(
        new Dictionary<string, object?> { [nameof(TvShowDetail.Id)] = "s1" },
        services => services.AddPageServices()
            .AddSingleton(new TvShowApiClient(_api.CreateClient()))
            .AddSingleton(new EpisodeApiClient(_api.CreateClient()))
            .AddSingleton(new ReferenceDataApiClient(_api.CreateClient())));
}
