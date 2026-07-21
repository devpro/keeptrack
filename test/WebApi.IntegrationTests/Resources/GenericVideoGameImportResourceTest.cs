using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public class GenericVideoGameImportResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task PreviewThenCommit_CreatesAVideoGame_AndSkipsADuplicateReimport()
    {
        await Authenticate();

        var csv = GenericVideoGameImportFixtureCsvBuilder.Build();

        var preview = await PostFileAsync<List<GenericVideoGameImportPreviewRowDto>>("/api/import/video-games/preview", "file", csv, "transactions.csv");
        var gameRow = preview.Should().Contain(r => r.Title == GenericVideoGameImportFixtureCsvBuilder.GameTitle).Subject;
        gameRow.Platform.Should().Be(GenericVideoGameImportFixtureCsvBuilder.GamePlatform);
        gameRow.ProductName.Should().Be(GenericVideoGameImportFixtureCsvBuilder.GameProductName);
        gameRow.AlreadyImported.Should().BeFalse();

        try
        {
            // a row with no platform must be rejected before anything is persisted
            var invalidItem = ToCommitItem(gameRow);
            invalidItem.Platform = null;
            var invalidRequest = new GenericVideoGameImportCommitRequestDto { Items = [invalidItem] };
            await PostAsync<GenericVideoGameImportCommitRequestDto, GenericVideoGameImportCommitResultDto>("/api/import/video-games/commit", invalidRequest, HttpStatusCode.BadRequest);

            var commitRequest = new GenericVideoGameImportCommitRequestDto { Items = [ToCommitItem(gameRow)] };
            var commitResult = await PostAsync<GenericVideoGameImportCommitRequestDto, GenericVideoGameImportCommitResultDto>("/api/import/video-games/commit", commitRequest);
            commitResult.VideoGamesCreated.Should().Be(1);

            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(GenericVideoGameImportFixtureCsvBuilder.GameTitle)}");
            var videoGame = videoGames.Items.Should().ContainSingle().Subject;
            videoGame.Platforms.Should().ContainSingle();
            videoGame.Platforms[0].Platform.Should().Be(GenericVideoGameImportFixtureCsvBuilder.GamePlatform);
            videoGame.Platforms[0].ProductName.Should().Be(GenericVideoGameImportFixtureCsvBuilder.GameProductName);
            videoGame.Platforms[0].CopyType.Should().Be(CopyType.Digital);
            videoGame.Platforms[0].Price.Should().Be(14.99m);
            videoGame.Platforms[0].Reference.Should().Contain(GenericVideoGameImportFixtureCsvBuilder.GameTransactionId);
            // SourceTitle is echoed from the preview row's already-cleaned Title (platform suffix already
            // stripped by CleanTitle during parsing), not the raw "Game Name (PS4)" CSV cell.
            videoGame.Notes.Should().Be($"Title from {GenericVideoGameImportFixtureCsvBuilder.GameVendor}: {GenericVideoGameImportFixtureCsvBuilder.GameTitle}");

            // re-preview after commit: the just-imported transaction must now be flagged, so re-uploading a
            // newer export later doesn't silently duplicate it
            var secondPreview = await PostFileAsync<List<GenericVideoGameImportPreviewRowDto>>("/api/import/video-games/preview", "file", csv, "transactions.csv");
            secondPreview.Should().Contain(r => r.Title == GenericVideoGameImportFixtureCsvBuilder.GameTitle && r.AlreadyImported);

            // committing the exact same row again must not duplicate anything
            var secondCommitResult = await PostAsync<GenericVideoGameImportCommitRequestDto, GenericVideoGameImportCommitResultDto>("/api/import/video-games/commit", commitRequest);
            secondCommitResult.VideoGamesCreated.Should().Be(0);
            secondCommitResult.VideoGamesMergedInto.Should().Be(0);
            secondCommitResult.VideoGamesSkipped.Should().Be(1);

            var videoGamesAfterReimport = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(GenericVideoGameImportFixtureCsvBuilder.GameTitle)}");
            videoGamesAfterReimport.Items.Should().ContainSingle().Which.Platforms.Should().ContainSingle();
        }
        finally
        {
            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(GenericVideoGameImportFixtureCsvBuilder.GameTitle)}");
            foreach (var videoGame in videoGames.Items.Where(g => g.Id is not null))
            {
                await DeleteAsync($"/api/video-games/{videoGame.Id}");
            }
        }
    }

    [Fact]
    public async Task Commit_MergesTwoRowsSharingATitle_IntoOneVideoGameWithTwoPlatforms()
    {
        await Authenticate();

        const string sharedTitle = "Keeptrack Video Game Import Test Multi-Platform Game";

        var request = new GenericVideoGameImportCommitRequestDto
        {
            Items =
            [
                new GenericVideoGameImportCommitItemDto
                {
                    RowId = "row-1", Title = sharedTitle, SourceTitle = sharedTitle, Platform = "PS4",
                    TransactionId = "111222333001", OrderId = "111222333002", Vendor = "PlayStation Store", CopyType = CopyType.Digital
                },
                new GenericVideoGameImportCommitItemDto
                {
                    RowId = "row-2", Title = sharedTitle, SourceTitle = sharedTitle, Platform = "PS5",
                    TransactionId = "111222333003", OrderId = "111222333004", Vendor = "PlayStation Store", CopyType = CopyType.Digital
                }
            ]
        };

        try
        {
            var commitResult = await PostAsync<GenericVideoGameImportCommitRequestDto, GenericVideoGameImportCommitResultDto>("/api/import/video-games/commit", request);
            commitResult.VideoGamesCreated.Should().Be(1);

            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(sharedTitle)}");
            var videoGame = videoGames.Items.Should().ContainSingle().Subject;
            videoGame.Platforms.Should().HaveCount(2);
            videoGame.Platforms.Select(p => p.Platform).Should().BeEquivalentTo(["PS4", "PS5"]);
        }
        finally
        {
            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(sharedTitle)}");
            foreach (var videoGame in videoGames.Items.Where(g => g.Id is not null))
            {
                await DeleteAsync($"/api/video-games/{videoGame.Id}");
            }
        }
    }

    [Fact]
    public async Task PreviewThenCommit_ImportsAllThreeLines_WhenTheyShareOneTransactionAndOrderButDifferentProducts()
    {
        // reproduces a real bug found against a real PSN export: three different "Far Cry 4" DLC packs were
        // bought in a single transaction, sharing one Transaction Id/Order Id - the Reference used to be
        // built from those two alone, so the second and third lines were wrongly skipped as "already
        // imported" duplicates of the first, and only 1 of the 3 platform entries actually got created
        await Authenticate();

        var csv = GenericVideoGameImportFixtureCsvBuilder.Build();

        try
        {
            var preview = await PostFileAsync<List<GenericVideoGameImportPreviewRowDto>>("/api/import/video-games/preview", "file", csv, "transactions.csv");
            var bundleRows = preview.Where(r => r.Title == GenericVideoGameImportFixtureCsvBuilder.BundleTitle).ToList();
            bundleRows.Should().HaveCount(3);
            bundleRows.Should().OnlyContain(r => !r.AlreadyImported);

            var commitRequest = new GenericVideoGameImportCommitRequestDto { Items = bundleRows.Select(ToCommitItem).ToList() };
            var commitResult = await PostAsync<GenericVideoGameImportCommitRequestDto, GenericVideoGameImportCommitResultDto>("/api/import/video-games/commit", commitRequest);
            commitResult.VideoGamesCreated.Should().Be(1);
            commitResult.VideoGamesSkipped.Should().Be(0);

            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(GenericVideoGameImportFixtureCsvBuilder.BundleTitle)}");
            var videoGame = videoGames.Items.Should().ContainSingle().Subject;
            videoGame.Platforms.Should().HaveCount(3);
            videoGame.Platforms.Select(p => p.ProductName).Should().BeEquivalentTo(
            [
                GenericVideoGameImportFixtureCsvBuilder.BundleProductA,
                GenericVideoGameImportFixtureCsvBuilder.BundleProductB,
                GenericVideoGameImportFixtureCsvBuilder.BundleProductC
            ]);
            videoGame.Platforms.Select(p => p.Reference).Distinct().Should().HaveCount(3);
        }
        finally
        {
            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(GenericVideoGameImportFixtureCsvBuilder.BundleTitle)}");
            foreach (var videoGame in videoGames.Items.Where(g => g.Id is not null))
            {
                await DeleteAsync($"/api/video-games/{videoGame.Id}");
            }
        }
    }

    private static GenericVideoGameImportCommitItemDto ToCommitItem(GenericVideoGameImportPreviewRowDto row) => new()
    {
        RowId = row.RowId,
        Title = row.Title,
        SourceTitle = row.Title,
        Platform = row.Platform,
        ProductName = row.ProductName,
        TransactionId = row.TransactionId,
        OrderId = row.OrderId,
        Vendor = row.Vendor,
        AcquiredAt = row.TransactionDate,
        Price = row.Price,
        CopyType = CopyType.Digital
    };
}
