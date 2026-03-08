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
    public async Task<List<MovieDto>> GetMoviesAsync()
    {
        await AuthorizeAsync();
        return await http.GetFromJsonAsync<List<MovieDto>>("/api/movies") ?? [];
    }

    public async Task<MovieDto?> GetMovieAsync(string id)
    {
        await AuthorizeAsync();
        return await http.GetFromJsonAsync<MovieDto>($"/api/movies/{id}");
    }

    public async Task AddMovieAsync(MovieDto movie)
    {
        await AuthorizeAsync();
        var response = await http.PostAsJsonAsync("/api/movies", movie);
        response.EnsureSuccessStatusCode();
    }

    public async Task UpdateMovieAsync(MovieDto movie)
    {
        await AuthorizeAsync();
        var response = await http.PutAsJsonAsync($"/api/movies/{movie.Id}", movie);
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteMovieAsync(string id)
    {
        await AuthorizeAsync();
        var response = await http.DeleteAsync($"/api/movies/{id}");
        response.EnsureSuccessStatusCode();
    }

    private async Task<string> GetTokenAsync()
    {
        var state = await authStateProvider.GetAuthenticationStateAsync();
        var uid = state.User.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? throw new UnauthorizedAccessException("Not authenticated");

        var (token, expiry) = tokenStore.Get(uid);

        if (token is null || DateTimeOffset.UtcNow >= expiry)
        {
            throw new TokenExpiredException();
        }

        return token;
    }

    private async Task AuthorizeAsync()
    {
        var token = await GetTokenAsync();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}

public sealed class TokenExpiredException() : Exception("Firebase ID token has expired. Please log in again.");
