using System.Net.Http.Headers;
using System.Security.Claims;
using KeepTrack.WebApi.Dto;
using Microsoft.AspNetCore.Components.Authorization;

namespace KeepTrack.BlazorApp.Services;

public sealed class MoviesApiClient(
    HttpClient http,
    ITokenStore tokenStore,
    AuthenticationStateProvider authStateProvider)
{
    //public async Task<PagedResult<MovieDto>> GetMoviesAsync(
    public async Task<List<MovieDto>> GetMoviesAsync(
        string search   = "",
        int    page     = 1,
        int    pageSize = 20)
    {
        await AuthorizeAsync();

        var query = $"/api/movies?search={Uri.EscapeDataString(search)}&page={page}&pageSize={pageSize}";
        // var result = await http.GetFromJsonAsync<PagedResult<MovieDto>>(query);
        // return result ?? new PagedResult<MovieDto>([], 0);
        var result = await http.GetFromJsonAsync<List<MovieDto>>(query);
        return result ?? [];
    }

    public async Task<MovieDto?> GetMovieAsync(string id)
    {
        await AuthorizeAsync();
        return await http.GetFromJsonAsync<MovieDto>($"/api/movies/{id}");
    }

    public async Task AddMovieAsync(MovieDto movie)
    {
        await AuthorizeAsync();
        (await http.PostAsJsonAsync("/api/movies", movie)).EnsureSuccessStatusCode();
    }

    public async Task UpdateMovieAsync(MovieDto movie)
    {
        await AuthorizeAsync();
        (await http.PutAsJsonAsync($"/api/movies/{movie.Id}", movie)).EnsureSuccessStatusCode();
    }

    public async Task DeleteMovieAsync(string id)
    {
        await AuthorizeAsync();
        (await http.DeleteAsync($"/api/movies/{id}")).EnsureSuccessStatusCode();
    }

    private async Task<string> GetUidAsync()
    {
        var state = await authStateProvider.GetAuthenticationStateAsync();
        return state.User.FindFirstValue(ClaimTypes.NameIdentifier)
               ?? throw new UnauthorizedAccessException("Not authenticated");
    }

    private async Task AuthorizeAsync()
    {
        var uid = await GetUidAsync();
        var (token, expiry) = tokenStore.Get(uid);

        if (token is null || DateTimeOffset.UtcNow >= expiry)
            throw new TokenExpiredException();

        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
    }
}

public sealed class TokenExpiredException() : Exception("Firebase ID token has expired. Please log in again.");

public record PagedResult<T>(List<T> Items, int TotalCount);
