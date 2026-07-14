using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class WishlistServiceTest
{
    private readonly WishlistService _service = new();

    [Fact]
    public void SortMovies_OrdersByTitleAscending()
    {
        var movies = new[]
        {
            new MovieModel { Id = "1", OwnerId = "owner", Title = "Zodiac" },
            new MovieModel { Id = "2", OwnerId = "owner", Title = "Arrival" }
        };

        var result = WishlistService.SortMovies(movies);

        result.Should().HaveCount(2);
        result[0].Title.Should().Be("Arrival");
        result[1].Title.Should().Be("Zodiac");
    }

    [Fact]
    public void SortTvShows_OrdersByTitleAscending()
    {
        var shows = new[]
        {
            new TvShowModel { Id = "1", OwnerId = "owner", Title = "Yellowjackets" },
            new TvShowModel { Id = "2", OwnerId = "owner", Title = "Dark" }
        };

        var result = WishlistService.SortTvShows(shows);

        result.Should().HaveCount(2);
        result[0].Title.Should().Be("Dark");
        result[1].Title.Should().Be("Yellowjackets");
    }

    [Fact]
    public void SortBooks_OrdersByTitleAscending()
    {
        var books = new[]
        {
            new BookModel { Id = "1", OwnerId = "owner", Title = "The Two Towers", Author = "Tolkien" },
            new BookModel { Id = "2", OwnerId = "owner", Title = "Dune", Author = "Herbert" }
        };

        var result = WishlistService.SortBooks(books);

        result.Should().HaveCount(2);
        result[0].Title.Should().Be("Dune");
        result[1].Title.Should().Be("The Two Towers");
    }

    [Fact]
    public void SortVideoGames_OrdersByTitleAscending()
    {
        var games = new[]
        {
            new VideoGameModel { Id = "1", OwnerId = "owner", Title = "Zelda", Platforms = [new VideoGamePlatformModel { Platform = "Switch", State = "Available" }] },
            new VideoGameModel { Id = "2", OwnerId = "owner", Title = "Elden Ring", Platforms = [new VideoGamePlatformModel { Platform = "PS5", State = "Available" }] }
        };

        var result = WishlistService.SortVideoGames(games);

        result.Should().HaveCount(2);
        result[0].Title.Should().Be("Elden Ring");
        result[1].Title.Should().Be("Zelda");
    }

    [Fact]
    public void SortMovies_ReturnsEmptyListWhenNoMoviesWishlisted()
    {
        var result = WishlistService.SortMovies([]);

        result.Should().BeEmpty();
    }
}
