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

public class AmazonImportResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task PreviewThenCommit_CreatesOneItemPerMediaType_AndFlagsThemAllAlreadyImportedOnReimport()
    {
        await Authenticate();

        var csv = AmazonFixtureCsvBuilder.Build();

        var preview = await PostFileAsync<List<AmazonOrderPreviewRowDto>>("/api/import/amazon/preview", "file", csv, "orders.csv");
        var bookRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.BookTitle).Subject;
        bookRow.LooksLikeBook.Should().BeTrue();
        bookRow.SuggestedIsbn.Should().Be(AmazonFixtureCsvBuilder.BookIsbn);
        bookRow.AlreadyImported.Should().BeFalse();

        var nonBookRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.NonBookTitle).Subject;
        nonBookRow.LooksLikeBook.Should().BeFalse();

        var movieRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.MovieTitle).Subject;
        var tvShowRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.TvShowTitle).Subject;
        var videoGameRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.VideoGameTitle).Subject;
        // none of these three have an ISBN-shaped ASIN - confirms the heuristic never mistakes them for books
        movieRow.LooksLikeBook.Should().BeFalse();
        tvShowRow.LooksLikeBook.Should().BeFalse();
        videoGameRow.LooksLikeBook.Should().BeFalse();

        try
        {
            // a video game row with no platform must be rejected before anything is persisted
            var invalidPlatformRequest = new AmazonImportCommitRequestDto { Items = [ToCommitItem(videoGameRow, AmazonImportMediaType.VideoGame, platform: null)] };
            await PostAsync<AmazonImportCommitRequestDto, AmazonImportCommitResultDto>("/api/import/amazon/commit", invalidPlatformRequest, HttpStatusCode.BadRequest);

            // a row with no media type chosen must also be rejected before anything is persisted
            var noMediaTypeItem = ToCommitItem(bookRow, AmazonImportMediaType.Book);
            noMediaTypeItem.MediaType = null;
            var invalidTypeRequest = new AmazonImportCommitRequestDto { Items = [noMediaTypeItem] };
            await PostAsync<AmazonImportCommitRequestDto, AmazonImportCommitResultDto>("/api/import/amazon/commit", invalidTypeRequest, HttpStatusCode.BadRequest);

            var commitRequest = new AmazonImportCommitRequestDto
            {
                Items =
                [
                    ToCommitItem(bookRow, AmazonImportMediaType.Book, isbn: bookRow.SuggestedIsbn, year: 1997),
                    ToCommitItem(movieRow, AmazonImportMediaType.Movie),
                    ToCommitItem(tvShowRow, AmazonImportMediaType.TvShow),
                    ToCommitItem(videoGameRow, AmazonImportMediaType.VideoGame, platform: "PS5")
                ]
            };

            var commitResult = await PostAsync<AmazonImportCommitRequestDto, AmazonImportCommitResultDto>("/api/import/amazon/commit", commitRequest);
            commitResult.BooksCreated.Should().Be(1);
            commitResult.MoviesCreated.Should().Be(1);
            commitResult.TvShowsCreated.Should().Be(1);
            commitResult.VideoGamesCreated.Should().Be(1);

            var books = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.BookTitle)}");
            var book = books.Items.Should().ContainSingle().Subject;
            book.Year.Should().Be(1997);
            book.Isbn.Should().Be(AmazonFixtureCsvBuilder.BookIsbn);
            book.OwnedVersions.Should().ContainSingle();
            book.OwnedVersions[0].Price.Should().Be(10.49m);
            book.OwnedVersions[0].Reference.Should().Contain(AmazonFixtureCsvBuilder.BookOrderId);
            book.Notes.Should().Be($"Title from Amazon: {AmazonFixtureCsvBuilder.BookTitle}\nISBN from Amazon: {AmazonFixtureCsvBuilder.BookIsbn}");

            var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.MovieTitle)}");
            var movie = movies.Items.Should().ContainSingle().Subject;
            movie.OwnedVersions.Should().ContainSingle();
            movie.Notes.Should().Be($"Title from Amazon: {AmazonFixtureCsvBuilder.MovieTitle}");

            var tvShows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.TvShowTitle)}");
            var tvShow = tvShows.Items.Should().ContainSingle().Subject;
            tvShow.OwnedVersions.Should().ContainSingle();

            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.VideoGameTitle)}");
            var videoGame = videoGames.Items.Should().ContainSingle().Subject;
            videoGame.Platforms.Should().ContainSingle();
            videoGame.Platforms[0].Platform.Should().Be("PS5");
            videoGame.Platforms[0].Reference.Should().Contain(AmazonFixtureCsvBuilder.VideoGameOrderId);

            // re-preview after commit: every just-imported order must now be flagged, regardless of which
            // type it was imported as, so re-uploading a newer export later doesn't silently duplicate any of them
            var secondPreview = await PostFileAsync<List<AmazonOrderPreviewRowDto>>("/api/import/amazon/preview", "file", csv, "orders.csv");
            secondPreview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.BookTitle && r.AlreadyImported);
            secondPreview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.MovieTitle && r.AlreadyImported);
            secondPreview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.TvShowTitle && r.AlreadyImported);
            secondPreview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.VideoGameTitle && r.AlreadyImported);

            // committing the exact same rows again (e.g. the user re-runs the import without noticing the
            // "already imported" badge) must not duplicate anything - this is the bug reported in practice
            var secondCommitResult = await PostAsync<AmazonImportCommitRequestDto, AmazonImportCommitResultDto>("/api/import/amazon/commit", commitRequest);
            secondCommitResult.BooksCreated.Should().Be(0);
            secondCommitResult.BooksMergedInto.Should().Be(0);
            secondCommitResult.BooksSkipped.Should().Be(1);
            secondCommitResult.MoviesSkipped.Should().Be(1);
            secondCommitResult.TvShowsSkipped.Should().Be(1);
            secondCommitResult.VideoGamesSkipped.Should().Be(1);

            var booksAfterReimport = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.BookTitle)}");
            booksAfterReimport.Items.Should().ContainSingle().Which.OwnedVersions.Should().ContainSingle();

            var videoGamesAfterReimport = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.VideoGameTitle)}");
            videoGamesAfterReimport.Items.Should().ContainSingle().Which.Platforms.Should().ContainSingle();
        }
        finally
        {
            var books = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.BookTitle)}");
            foreach (var book in books.Items.Where(b => b.Id is not null))
            {
                await DeleteAsync($"/api/books/{book.Id}");
            }

            var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.MovieTitle)}");
            foreach (var movie in movies.Items.Where(m => m.Id is not null))
            {
                await DeleteAsync($"/api/movies/{movie.Id}");
            }

            var tvShows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.TvShowTitle)}");
            foreach (var tvShow in tvShows.Items.Where(t => t.Id is not null))
            {
                await DeleteAsync($"/api/tv-shows/{tvShow.Id}");
            }

            var videoGames = await GetAsync<PagedResult<VideoGameDto>>($"/api/video-games?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.VideoGameTitle)}");
            foreach (var videoGame in videoGames.Items.Where(g => g.Id is not null))
            {
                await DeleteAsync($"/api/video-games/{videoGame.Id}");
            }
        }
    }

    private static AmazonImportCommitItemDto ToCommitItem(AmazonOrderPreviewRowDto row, AmazonImportMediaType mediaType, int? year = null, string? isbn = null, string? platform = null) => new()
    {
        RowId = row.RowId,
        Title = row.Title,
        AmazonTitle = row.Title,
        MediaType = mediaType,
        Year = year,
        Isbn = isbn,
        Platform = platform,
        AcquiredAt = row.OrderDate,
        Price = row.Price,
        Vendor = row.Vendor,
        Reference = $"Amazon order {row.OrderId}",
        CopyType = CopyType.Physical
    };
}
