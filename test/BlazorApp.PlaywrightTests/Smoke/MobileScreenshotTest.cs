using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Not a regression test: a visual-review harness that seeds representative items via the API
/// (including reference-linked movies/shows/albums/games with real cover art),
/// captures full-page screenshots of every page at a phone viewport (390x844), then deletes everything it created.
/// Assertion-free by design - its output is the screenshots, reviewed by a human (or an AI assistant) after UI changes.
/// Doubly gated: besides the usual E2E_ENABLED, it also skips unless E2E_SCREENSHOTS=true,
/// so a normal full e2e run doesn't pay for the slow walkthrough.
/// Output directory: E2E_SHOTS_DIR.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class MobileScreenshotTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    private static readonly (string Route, string Name)[] s_routes =
    [
        ("/", "home"),
        ("/add", "quickadd-picker"),
        ("/add?type=movie", "quickadd-movie-form"),
        ("/watch-next", "watch-next"),
        ("/wishlist", "wishlist"),
        ("/books", "books"),
        ("/movies", "movies"),
        ("/albums", "albums"),
        ("/playlists", "playlists"),
        ("/tv-shows", "tv-shows"),
        ("/video-games", "video-games"),
        ("/cars", "cars"),
        ("/houses", "houses"),
        ("/health", "health"),
        ("/import", "import"),
        ("/admin/reference-data", "admin-reference-data")
    ];

    private static string ShotsDirectory =>
        End2EndConfiguration.ScreenshotsDirectory ?? Path.Combine(AppContext.BaseDirectory, "mobile-shots");

    public override BrowserNewContextOptions ContextOptions()
    {
        var options = base.ContextOptions();
        options.ViewportSize = new ViewportSize { Width = 390, Height = 844 };
        options.DeviceScaleFactor = 2;
        options.IsMobile = true;
        options.HasTouch = true;
        return options;
    }

    [Fact]
    public async Task CaptureAllPagesAtPhoneViewport()
    {
        Assert.SkipUnless(End2EndConfiguration.Screenshots, "E2E_SCREENSHOTS is not set; the visual-review capture is opt-in.");
        SkipIfReadOnly();
        Directory.CreateDirectory(ShotsDirectory);

        var api = Fixture.ApiHttpClient;
        var created = new List<string>();
        try
        {
            await SeedAsync(api, created);

            foreach (var (route, name) in s_routes)
            {
                await CaptureAsync(route, name);
            }

            // The collapsed sidebar opened via the hamburger toggle.
            await Page.GotoAsync("/");
            await Page.WaitForTimeoutAsync(500);
            await Page.Locator("label.navbar-toggler-label").ClickAsync();
            await Page.WaitForTimeoutAsync(300);
            await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, "nav-open.png"), FullPage = false });

            await CaptureFirstDetailAsync("/movies", "movie-detail");
            await CaptureFirstDetailAsync("/tv-shows", "tvshow-detail");
            await CaptureFirstDetailAsync("/cars", "car-detail");
            await CaptureFirstDetailAsync("/books", "book-detail");
            await CaptureFirstDetailAsync("/health", "health-detail");
            // targeted by title (not "first") so these two land on the CustomImageUrl-seeded items specifically,
            // not whichever item happens to sort first in a list that grows over time
            await CaptureDetailByTitleAsync("/video-games", "Hades", "video-game-detail");
            await CaptureDetailByTitleAsync("/albums", "Nevermind", "album-detail");

            // The Add form modal on a list page.
            await Page.GotoAsync("/movies");
            await Page.WaitForTimeoutAsync(1000);
            await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Add" }).First.ClickAsync();
            await Page.WaitForTimeoutAsync(500);
            await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, "movies-add-form.png"), FullPage = true });

            // The admin unresolved queue with the first row's inline search panel expanded (no linking).
            await Page.GotoAsync("/admin/reference-data");
            await Page.WaitForTimeoutAsync(1500);
            var wireRow = Page.Locator(".kt-table-wrap table tbody tr", new PageLocatorOptions { HasText = "The Wire" }).First;
            if (await wireRow.CountAsync() > 0)
            {
                for (var attempt = 0; attempt < 3; attempt++)
                {
                    await wireRow.ClickAsync();
                    try
                    {
                        await Assertions.Expect(Page.GetByPlaceholder("Title")).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 2000 });
                        break;
                    }
                    catch (PlaywrightException)
                    {
                    }
                }

                await Page.WaitForTimeoutAsync(3000);
                await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, "admin-expanded.png"), FullPage = true });
            }

            // The Albums queue: the expanded panel must prefill the tenant's saved artist.
            await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Albums" }).ClickAsync();
            await Page.WaitForTimeoutAsync(1000);
            var albumRow = Page.Locator(".kt-table-wrap table tbody tr", new PageLocatorOptions { HasText = "Zzq Unfindable Album" }).First;
            if (await albumRow.CountAsync() > 0)
            {
                for (var attempt = 0; attempt < 3; attempt++)
                {
                    await albumRow.ClickAsync();
                    try
                    {
                        await Assertions.Expect(Page.GetByPlaceholder("Artist")).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 2000 });
                        break;
                    }
                    catch (PlaywrightException)
                    {
                    }
                }

                await Page.WaitForTimeoutAsync(3000);
                await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, "admin-album-expanded.png"), FullPage = true });
            }

            await Page.SetViewportSizeAsync(1280, 900);
            await CaptureFirstDetailAsync("/video-games", "video-game-detail-desktop");

            // A dark-theme sample of the densest pages.
            await Page.EmulateMediaAsync(new PageEmulateMediaOptions { ColorScheme = ColorScheme.Dark });
            await CaptureAsync("/movies", "movies-dark");
            await CaptureAsync("/watch-next", "watch-next-dark");
        }
        finally
        {
            foreach (var path in created)
            {
                await Fixture.DeleteItemAsync(path);
            }
        }
    }

    private static async Task SeedAsync(HttpClient api, List<string> created)
    {
        await CreateAsync(api, created, "api/movies", new MovieDto
        {
            Title = "The Shawshank Redemption",
            Year = 1994,
            Rating = 4.5f,
            IsFavorite = true,
            FirstSeenAt = new DateOnly(2024, 3, 12)
        });
        await CreateAsync(api, created, "api/movies", new MovieDto
        {
            Title = "Heat",
            Year = 1995,
            Rating = 4,
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, Price = 14.99m, Vendor = "Fnac", Reference = "Blu-ray" }],
            FirstSeenAt = new DateOnly(2023, 11, 2)
        });
        await CreateAsync(api, created, "api/movies", new MovieDto { Title = "Everything Everywhere All at Once", Year = 2022, WantToWatch = true });
        await CreateAsync(api, created, "api/movies", new MovieDto
        {
            Title = "The Terminator",
            Year = 1984,
            Rating = 4,
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Digital }],
            FirstSeenAt = new DateOnly(2022, 7, 30)
        });
        await CreateAsync(api, created, "api/movies", new MovieDto { Title = "Blade Runner 2049", Year = 2017, WantToWatch = true, IsWishlisted = true });
        await CreateAsync(api, created, "api/movies", new MovieDto { Title = "Amélie", Year = 2001, Rating = 3.5f, FirstSeenAt = new DateOnly(2021, 1, 15) });

        await CreateAsync(api, created, "api/tv-shows", new TvShowDto
        {
            Title = "Breaking Bad",
            Year = 2008,
            Rating = 5,
            State = TvShowStatus.Finished,
            IsFavorite = true,
            LastEpisodeSeen = "S05E16"
        });
        await CreateAsync(api, created, "api/tv-shows", new TvShowDto
        {
            Title = "Severance",
            Year = 2022,
            Rating = 4.5f,
            State = TvShowStatus.Current,
            LastEpisodeSeen = "S02E03"
        });
        await CreateAsync(api, created, "api/tv-shows", new TvShowDto { Title = "The Wire", Year = 2002, State = TvShowStatus.Stopped, LastEpisodeSeen = "S03E01" });

        // A realistic long unresolved queue: gibberish titles that no provider can match, so they all land
        // in the admin queue alongside The Wire (whose two real TMDB candidates keep it unresolved too).
        for (var i = 1; i <= 12; i++)
        {
            await CreateAsync(api, created, "api/tv-shows", new TvShowDto { Title = $"Zzq Unmatchable Show {i:00}", Year = 1990 + i });
        }

        await CreateAsync(api, created, "api/books", new BookDto
        {
            Title = "Killing Floor",
            Author = "Lee Child",
            Series = "Jack Reacher",
            Year = 1997,
            Rating = 4,
            Genre = "Thriller",
            FirstReadAt = new DateOnly(2024, 8, 3)
        });

        // An album (square Discogs art) and a game (wide RAWG art) - linked deterministically via the admin
        // search/link API rather than relying on the background auto-resolve winning the race.
        await CreateAsync(api, created, "api/albums", new AlbumDto
        {
            Title = "Nevermind",
            Artist = "Nirvana",
            Year = 1991,
            Rating = 4.5f,
            IsFavorite = true,
            // proves the CustomImageUrl override shows up on both the list thumbnail and the detail cover,
            // taking priority over the linked Discogs cover it's about to be linked to below
            CustomImageUrl = "https://picsum.photos/seed/nevermind-custom-cover/400/400"
        });
        await CreateAsync(api, created, "api/video-games", new VideoGameDto
        {
            Title = "Hades",
            Year = 2020,
            Rating = 4.5f,
            // a game's copies are its platform entries - there is no separate owned flag anymore
            Platforms = [new VideoGamePlatformDto { Platform = "PC", CopyType = CopyType.Digital, State = "Current" }],
            // proves the CustomImageUrl override shows up on both the list thumbnail and the detail cover,
            // taking priority over the linked RAWG cover it's about to be linked to below
            CustomImageUrl = "https://picsum.photos/seed/hades-custom-cover/600/300"
        });
        await LinkFirstCandidateAsync(api, ReferenceItemType.Album, "Nevermind", 1991, "Nirvana");
        await LinkFirstCandidateAsync(api, ReferenceItemType.VideoGame, "Hades", 2020, null);

        // a health journal with a settled appointment, an unbalanced one (drives the "to check" panel)
        // and a sickness entry, so the detail shot shows every section
        var healthProfileId = await CreateAsync(api, created, "api/health-profiles", new HealthProfileDto { Name = "Bertrand" });
        await CreateAsync(api, created, "api/health-records", new HealthRecordDto
        {
            HealthProfileId = healthProfileId,
            HistoryDate = new DateTime(2026, 2, 3, 9, 30, 0),
            EventType = HealthEventType.Appointment,
            Specialty = "généraliste",
            Practitioner = "Dr Martin",
            Description = "Annual check-up",
            Price = 30,
            PublicReimbursement = 20,
            InsuranceReimbursement = 8.5,
            NotCovered = 1.5
        });
        await CreateAsync(api, created, "api/health-records", new HealthRecordDto
        {
            HealthProfileId = healthProfileId,
            HistoryDate = new DateTime(2026, 5, 12, 14, 0, 0),
            EventType = HealthEventType.Appointment,
            Specialty = "dentiste",
            Practitioner = "Dr Diaz",
            Description = "Descaling",
            Price = 120
        });
        await CreateAsync(api, created, "api/health-records", new HealthRecordDto
        {
            HealthProfileId = healthProfileId,
            HistoryDate = new DateTime(2026, 7, 1, 8, 0, 0),
            EventType = HealthEventType.Sickness,
            Description = "Fever, stayed home"
        });

        // stays unresolved (no provider can match it) - proves the admin queue prefills the saved artist
        await CreateAsync(api, created, "api/albums", new AlbumDto { Title = "Zzq Unfindable Album", Artist = "Zzq Test Artist", Year = 1999 });
        await CreateAsync(api, created, "api/books", new BookDto
        {
            Title = "The Return of the King",
            Author = "J. R. R. Tolkien",
            Series = "The Lord of the Rings",
            Year = 1955,
            Rating = 5,
            IsFavorite = true,
            IsWishlisted = true
        });

        var carId = await CreateAsync(api, created, "api/cars", new CarDto
        {
            Name = "Daily driver",
            Manufacturer = "Renault",
            Model = "Clio V",
            Year = 2019,
            LicensePlate = "AB-123-CD",
            EnergyType = CarEnergyType.Combustion
        });
        var mileage = 42000;
        for (var i = 0; i < 6; i++)
        {
            mileage += 550 + (i * 35);
            await CreateAsync(api, created, "api/car-history",
                new CarHistoryDto
                {
                    CarId = carId,
                    HistoryDate = DateTime.UtcNow.AddMonths(i - 6).AddDays(3),
                    EventType = CarHistoryType.Refuel,
                    Mileage = mileage,
                    DeltaMileage = 550 + (i * 35),
                    FuelCategory = "E10",
                    FuelVolume = 38.2 + i,
                    FuelUnitPrice = 1.78,
                    Cost = Math.Round((38.2 + i) * 1.78, 2),
                    IsFullRefill = true,
                    StationBrandName = "TotalEnergies",
                    City = "Lyon"
                });
        }

        await CreateAsync(api, created, "api/car-history",
            new CarHistoryDto
            {
                CarId = carId,
                HistoryDate = DateTime.UtcNow.AddMonths(-2),
                EventType = CarHistoryType.Maintenance,
                Mileage = mileage - 300,
                Description = "Oil change + front brake pads",
                Cost = 389.90,
                Garage = "Renault Lyon Est"
            });
    }

    /// <summary>Links an item to its provider's first search candidate via the admin API (best-effort).</summary>
    private static async Task LinkFirstCandidateAsync(HttpClient api, ReferenceItemType type, string title, int year, string? creator)
    {
        var query = $"api/reference-data/search?type={type}&title={Uri.EscapeDataString(title)}&year={year}"
                    + (creator is null ? "" : $"&creator={Uri.EscapeDataString(creator)}");
        var candidates = await api.GetFromJsonAsync<List<ReferenceSearchResultDto>>(query);
        if (candidates is not { Count: > 0 }) return;

        var response = await api.PostAsJsonAsync("api/reference-data/link",
            new LinkReferenceRequestDto { Type = type, Title = title, Year = year, ExternalId = candidates[0].ExternalId });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Creates the item, records "api/x/{id}" for cleanup, returns the new id.</summary>
    private static async Task<string> CreateAsync<TDto>(HttpClient api, List<string> created, string path, TDto dto)
    {
        var response = await api.PostAsJsonAsync(path, dto);
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var id = body.RootElement.GetProperty("id").GetString()!;
        created.Add($"{path}/{id}");
        return id;
    }

    private async Task CaptureAsync(string route, string name)
    {
        await Page.GotoAsync(route);
        await Assertions.Expect(Page.Locator("#blazor-error-ui")).ToBeHiddenAsync();
        // No networkidle with a live SignalR circuit - give data loads a moment to settle instead.
        await Page.WaitForTimeoutAsync(1200);
        await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, $"{name}.png"), FullPage = true });
    }

    private async Task CaptureFirstDetailAsync(string listRoute, string name)
    {
        await Page.GotoAsync(listRoute);
        await Page.WaitForTimeoutAsync(1200);
        var firstItemLink = Page.Locator($"main a[href^='{listRoute}/']").First;
        if (await firstItemLink.CountAsync() == 0)
        {
            return;
        }

        await firstItemLink.ClickAsync();
        await Page.WaitForTimeoutAsync(1500);
        await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, $"{name}.png"), FullPage = true });
    }

    private async Task CaptureDetailByTitleAsync(string listRoute, string title, string name)
    {
        await Page.GotoAsync(listRoute);
        await Page.WaitForTimeoutAsync(1200);
        var itemLink = Page.Locator($"main a[href^='{listRoute}/']", new PageLocatorOptions { HasText = title }).First;
        if (await itemLink.CountAsync() == 0)
        {
            return;
        }

        await itemLink.ClickAsync();
        await Page.WaitForTimeoutAsync(1500);
        await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(ShotsDirectory, $"{name}.png"), FullPage = true });
    }
}
