using KeepTrack.Common.Collections.Generic;
using KeepTrack.WebApi.Contracts.Dto;

namespace KeepTrack.BlazorApp.Services;

public sealed class MoviesApiClient(HttpClient http)
{
    public async Task<PagedResult<MovieDto>> GetMoviesAsync(string search, int page, int pageSize)
    {
        var query = $"/api/movies?search={Uri.EscapeDataString(search)}&page={page}&pageSize={pageSize}";
        var result = await http.GetFromJsonAsync<PagedResult<MovieDto>>(query);
        return result ?? new PagedResult<MovieDto>([], 0, 1, 1);
    }

    public async Task<MovieDto?> GetMovieAsync(string id)
    {
        return await http.GetFromJsonAsync<MovieDto>($"/api/movies/{id}");
    }

    public async Task AddMovieAsync(MovieDto movie)
    {
        (await http.PostAsJsonAsync("/api/movies", movie)).EnsureSuccessStatusCode();
    }

    public async Task UpdateMovieAsync(MovieDto movie)
    {
        (await http.PutAsJsonAsync($"/api/movies/{movie.Id}", movie)).EnsureSuccessStatusCode();
    }

    public async Task DeleteMovieAsync(string id)
    {
        (await http.DeleteAsync($"/api/movies/{id}")).EnsureSuccessStatusCode();
    }
}
