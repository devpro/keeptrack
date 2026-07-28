using System.Text;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Sharing;

/// <summary>A search/sort/filter query for one page of a shared category.</summary>
public sealed record SharedListQuery(string Search, int Page, int PageSize, string Sort, IReadOnlyDictionary<string, string> Filters);

/// <summary>
/// The recipient side of sharing - browse the collections others have shared with the caller (with the same
/// search/filter/sort the caller's own lists have) and copy media items into the caller's own collection
/// (<c>/api/shared-with-me</c>). Authenticated like every other client: the server matches the caller's own
/// email against each grant, so this is not an anonymous read.
/// </summary>
public sealed class SharedWithMeApiClient(HttpClient http)
{
    public async Task<List<SharedCollectionSummaryDto>> GetSharedWithMeAsync()
    {
        var result = await http.GetFromJsonAsync<List<SharedCollectionSummaryDto>>("/api/shared-with-me");
        return result ?? [];
    }

    public Task<SharedCategoryPageDto<MovieDto>?> GetMoviesAsync(string shareId, SharedListQuery query) => GetPageAsync<MovieDto>(shareId, "movies", query);
    public Task<SharedCategoryPageDto<TvShowDto>?> GetTvShowsAsync(string shareId, SharedListQuery query) => GetPageAsync<TvShowDto>(shareId, "tv-shows", query);
    public Task<SharedCategoryPageDto<BookDto>?> GetBooksAsync(string shareId, SharedListQuery query) => GetPageAsync<BookDto>(shareId, "books", query);
    public Task<SharedCategoryPageDto<AlbumDto>?> GetAlbumsAsync(string shareId, SharedListQuery query) => GetPageAsync<AlbumDto>(shareId, "albums", query);
    public Task<SharedCategoryPageDto<VideoGameDto>?> GetVideoGamesAsync(string shareId, SharedListQuery query) => GetPageAsync<VideoGameDto>(shareId, "video-games", query);

    public Task<CopyResultDto<MovieDto>?> CopyMovieAsync(string shareId, string itemId) => CopyAsync<MovieDto>(shareId, "movies", itemId);
    public Task<CopyResultDto<TvShowDto>?> CopyTvShowAsync(string shareId, string itemId) => CopyAsync<TvShowDto>(shareId, "tv-shows", itemId);
    public Task<CopyResultDto<BookDto>?> CopyBookAsync(string shareId, string itemId) => CopyAsync<BookDto>(shareId, "books", itemId);
    public Task<CopyResultDto<AlbumDto>?> CopyAlbumAsync(string shareId, string itemId) => CopyAsync<AlbumDto>(shareId, "albums", itemId);
    public Task<CopyResultDto<VideoGameDto>?> CopyVideoGameAsync(string shareId, string itemId) => CopyAsync<VideoGameDto>(shareId, "video-games", itemId);

    private Task<SharedCategoryPageDto<TDto>?> GetPageAsync<TDto>(string shareId, string segment, SharedListQuery query)
    {
        var url = new StringBuilder($"/api/shared-with-me/{shareId}/{segment}?page={query.Page}&pageSize={query.PageSize}");
        if (!string.IsNullOrEmpty(query.Search))
        {
            url.Append("&search=").Append(Uri.EscapeDataString(query.Search));
        }
        if (!string.IsNullOrEmpty(query.Sort))
        {
            url.Append("&sort=").Append(Uri.EscapeDataString(query.Sort));
        }
        foreach (var (key, value) in query.Filters)
        {
            url.Append('&').Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
        }

        return http.GetFromJsonAsync<SharedCategoryPageDto<TDto>>(url.ToString());
    }

    private async Task<CopyResultDto<TDto>?> CopyAsync<TDto>(string shareId, string segment, string itemId)
    {
        var response = await http.PostAsync($"/api/shared-with-me/{shareId}/{segment}/{itemId}/copy", null);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<CopyResultDto<TDto>>();
    }
}
