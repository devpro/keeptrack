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

public class GenericImportResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task PreviewThenCommit_CreatesOneItemPerTypeFromTheTypeColumn_AndDedupsOnReimport()
    {
        await Authenticate();

        var csv = GenericImportFixtureCsvBuilder.Build();

        var preview = await PostFileAsync<List<GenericImportPreviewRowDto>>("/api/import/generic/preview", "file", csv, "orders.csv");

        var bookRow = preview.Should().Contain(r => r.Title == GenericImportFixtureCsvBuilder.BookTitle).Subject;
        // the "Type" column pre-selects each row's media type - no per-row guessing needed
        bookRow.SuggestedMediaType.Should().Be(ImportMediaType.Book);
        bookRow.Author.Should().Be(GenericImportFixtureCsvBuilder.BookAuthor);
        bookRow.Vendor.Should().Be(GenericImportFixtureCsvBuilder.Vendor);
        bookRow.Website.Should().Be(GenericImportFixtureCsvBuilder.BookWebsite);
        bookRow.Condition.Should().Be(GenericImportFixtureCsvBuilder.BookCondition);
        bookRow.AlreadyImported.Should().BeFalse();

        var movieRow = preview.Should().Contain(r => r.Title == GenericImportFixtureCsvBuilder.MovieTitle).Subject;
        movieRow.SuggestedMediaType.Should().Be(ImportMediaType.Movie);

        var videoGameRow = preview.Should().Contain(r => r.Title == GenericImportFixtureCsvBuilder.VideoGameTitle).Subject;
        videoGameRow.SuggestedMediaType.Should().Be(ImportMediaType.VideoGame);
        videoGameRow.Platform.Should().Be(GenericImportFixtureCsvBuilder.VideoGamePlatform);

        // the commit creates items whose ids this test never sees, so cleanup is keyed on the fixture's own
        // synthetic titles - and registered before the commit, so a partial commit is cleaned up too
        TrackResourcesMatching<BookDto>("/api/books", GenericImportFixtureCsvBuilder.BookTitle);
        TrackResourcesMatching<MovieDto>("/api/movies", GenericImportFixtureCsvBuilder.MovieTitle);
        TrackResourcesMatching<VideoGameDto>("/api/video-games", GenericImportFixtureCsvBuilder.VideoGameTitle);

        // a video game row with no platform must be rejected before anything is persisted
        var invalidPlatformRequest = new GenericImportCommitRequestDto { Items = [ToCommitItem(videoGameRow, ImportMediaType.VideoGame, platform: null)] };
        await PostAsync<GenericImportCommitRequestDto, GenericImportCommitResultDto>("/api/import/generic/commit", invalidPlatformRequest, HttpStatusCode.BadRequest);

        // a row with no media type chosen must also be rejected before anything is persisted
        var noTypeRequest = new GenericImportCommitRequestDto { Items = [ToCommitItem(bookRow, mediaType: null)] };
        await PostAsync<GenericImportCommitRequestDto, GenericImportCommitResultDto>("/api/import/generic/commit", noTypeRequest, HttpStatusCode.BadRequest);

        var commitRequest = new GenericImportCommitRequestDto
        {
            Items =
            [
                ToCommitItem(bookRow, ImportMediaType.Book, author: bookRow.Author, year: 1969),
                ToCommitItem(movieRow, ImportMediaType.Movie),
                ToCommitItem(videoGameRow, ImportMediaType.VideoGame, platform: GenericImportFixtureCsvBuilder.VideoGamePlatform)
            ]
        };

        var commitResult = await PostAsync<GenericImportCommitRequestDto, GenericImportCommitResultDto>("/api/import/generic/commit", commitRequest);
        commitResult.BooksCreated.Should().Be(1);
        commitResult.MoviesCreated.Should().Be(1);
        commitResult.VideoGamesCreated.Should().Be(1);
        commitResult.RowsImported.Should().Be(3);
        commitResult.SkippedRowTitles.Should().BeEmpty();

        var books = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(GenericImportFixtureCsvBuilder.BookTitle)}");
        var book = books.Items.Should().ContainSingle().Subject;
        book.Year.Should().Be(1969);
        book.Author.Should().Be(GenericImportFixtureCsvBuilder.BookAuthor);
        book.OwnedVersions.Should().ContainSingle();
        book.OwnedVersions[0].Price.Should().Be(12.50m);
        // Vendor field comes from the Vendor column; the Reference carries the Website column (independent).
        book.OwnedVersions[0].Vendor.Should().Be(GenericImportFixtureCsvBuilder.Vendor);
        book.OwnedVersions[0].Reference.Should().Contain(GenericImportFixtureCsvBuilder.BookOrderId);
        book.OwnedVersions[0].Reference.Should().Contain(GenericImportFixtureCsvBuilder.BookWebsite);
        // the condition is preserved on the owned copy's Product field rather than dropped
        book.OwnedVersions[0].ProductName.Should().Be(GenericImportFixtureCsvBuilder.BookCondition);
        book.Notes.Should().Be($"Title from {GenericImportFixtureCsvBuilder.Vendor}: {GenericImportFixtureCsvBuilder.BookTitle}");

        var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(GenericImportFixtureCsvBuilder.MovieTitle)}");
        movies.Items.Should().ContainSingle().Which.OwnedVersions.Should().ContainSingle();

        var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(GenericImportFixtureCsvBuilder.VideoGameTitle)}");
        var videoGame = videoGames.Items.Should().ContainSingle().Subject;
        videoGame.Platforms.Should().ContainSingle();
        videoGame.Platforms[0].Platform.Should().Be(GenericImportFixtureCsvBuilder.VideoGamePlatform);
        videoGame.Platforms[0].Reference.Should().Contain(GenericImportFixtureCsvBuilder.VideoGameOrderId);

        // re-preview after commit: every just-imported order line must now be flagged as already imported
        var secondPreview = await PostFileAsync<List<GenericImportPreviewRowDto>>("/api/import/generic/preview", "file", csv, "orders.csv");
        secondPreview.Should().Contain(r => r.Title == GenericImportFixtureCsvBuilder.BookTitle && r.AlreadyImported);
        secondPreview.Should().Contain(r => r.Title == GenericImportFixtureCsvBuilder.MovieTitle && r.AlreadyImported);
        secondPreview.Should().Contain(r => r.Title == GenericImportFixtureCsvBuilder.VideoGameTitle && r.AlreadyImported);

        // committing the exact same rows again must not duplicate anything, and must reconcile as all-skipped
        var secondCommitResult = await PostAsync<GenericImportCommitRequestDto, GenericImportCommitResultDto>("/api/import/generic/commit", commitRequest);
        secondCommitResult.BooksCreated.Should().Be(0);
        secondCommitResult.BooksSkipped.Should().Be(1);
        secondCommitResult.MoviesSkipped.Should().Be(1);
        secondCommitResult.VideoGamesSkipped.Should().Be(1);
        secondCommitResult.RowsImported.Should().Be(0);
        secondCommitResult.SkippedRowTitles.Should().HaveCount(3);

        var booksAfterReimport = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(GenericImportFixtureCsvBuilder.BookTitle)}");
        booksAfterReimport.Items.Should().ContainSingle().Which.OwnedVersions.Should().ContainSingle();
    }

    private static GenericImportCommitItemDto ToCommitItem(GenericImportPreviewRowDto row, ImportMediaType? mediaType, int? year = null, string? author = null, string? platform = null) => new()
    {
        RowId = row.RowId,
        Title = row.Title,
        SourceTitle = row.Title,
        MediaType = mediaType,
        Year = year,
        Author = author,
        Isbn = row.Isbn,
        Platform = platform,
        Condition = row.Condition,
        OrderId = row.OrderId,
        ProductId = row.ProductId,
        Vendor = row.Vendor,
        Website = row.Website,
        AcquiredAt = row.OrderDate,
        Price = row.Price,
        CopyType = row.CopyType
    };
}
