using System;
using System.Collections.Generic;
using System.Linq;
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
    public async Task PreviewThenCommit_CreatesABookWithAnOwnedVersion_AndFlagsItAlreadyImportedOnReimport()
    {
        await Authenticate();

        var csv = AmazonFixtureCsvBuilder.Build();

        var preview = await PostFileAsync<List<AmazonOrderPreviewRowDto>>("/api/import/amazon/preview", "file", csv, "orders.csv");
        var bookRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.BookTitle).Subject;
        bookRow.LooksLikeBook.Should().BeTrue();
        bookRow.SuggestedIsbn.Should().Be(AmazonFixtureCsvBuilder.BookIsbn);
        bookRow.AlreadyImported.Should().BeFalse();
        bookRow.OrderId.Should().Be(AmazonFixtureCsvBuilder.BookOrderId);

        var nonBookRow = preview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.NonBookTitle).Subject;
        nonBookRow.LooksLikeBook.Should().BeFalse();

        try
        {
            var commitRequest = new AmazonImportCommitRequestDto
            {
                Items =
                [
                    new AmazonImportCommitItemDto
                    {
                        RowId = bookRow.RowId,
                        Title = bookRow.Title,
                        AmazonTitle = bookRow.Title,
                        Year = 1997,
                        Isbn = bookRow.SuggestedIsbn,
                        AcquiredAt = bookRow.OrderDate,
                        Price = bookRow.Price,
                        Vendor = bookRow.Vendor,
                        Reference = $"Amazon order {bookRow.OrderId}",
                        CopyType = CopyType.Physical
                    }
                ]
            };

            var commitResult = await PostAsync<AmazonImportCommitRequestDto, AmazonImportCommitResultDto>("/api/import/amazon/commit", commitRequest);
            commitResult.BooksCreated.Should().Be(1);
            commitResult.BooksMergedInto.Should().Be(0);
            commitResult.OwnedVersionsAdded.Should().Be(1);

            var books = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.BookTitle)}");
            var book = books.Items.Should().ContainSingle().Subject;
            book.Year.Should().Be(1997);
            book.Isbn.Should().Be(AmazonFixtureCsvBuilder.BookIsbn);
            book.OwnedVersions.Should().ContainSingle();
            book.OwnedVersions[0].Price.Should().Be(10.49m);
            book.OwnedVersions[0].Reference.Should().Contain(AmazonFixtureCsvBuilder.BookOrderId);
            book.Notes.Should().Be($"Title from Amazon: {AmazonFixtureCsvBuilder.BookTitle}\nISBN from Amazon: {AmazonFixtureCsvBuilder.BookIsbn}");

            // re-preview after commit: the just-imported order must now be flagged, so re-uploading a
            // newer export later doesn't silently duplicate this book
            var secondPreview = await PostFileAsync<List<AmazonOrderPreviewRowDto>>("/api/import/amazon/preview", "file", csv, "orders.csv");
            secondPreview.Should().Contain(r => r.Title == AmazonFixtureCsvBuilder.BookTitle && r.AlreadyImported);
        }
        finally
        {
            var books = await GetAsync<PagedResult<BookDto>>($"/api/books?search={Uri.EscapeDataString(AmazonFixtureCsvBuilder.BookTitle)}");
            foreach (var book in books.Items.Where(b => b.Id is not null))
            {
                await DeleteAsync($"/api/books/{book.Id}");
            }
        }
    }
}
