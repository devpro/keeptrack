using Keeptrack.Common.System;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public abstract class InventoryApiClientBase<TDto>(HttpClient http, bool hasReference = false)
    where TDto : IHasId
{
    private sealed record ApiError(string? Error);

    protected abstract string ApiResourceName { get; }

    /// <summary>
    /// Exposes the HttpClient to subclasses that add their own calls (e.g. a refresh-reference endpoint) -
    /// lets them reuse this instance instead of capturing their own <c>HttpClient</c> primary-constructor parameter as a second field holding the same reference.
    /// </summary>
    protected HttpClient Http => http;

    public async Task<PagedResult<TDto>> GetAsync(string search, int page, int pageSize, IReadOnlyDictionary<string, string>? extraQuery = null, string? sort = null)
    {
        var query = $"{ApiResourceName}?search={Uri.EscapeDataString(search)}&page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(sort))
        {
            query += $"&sort={Uri.EscapeDataString(sort)}";
        }
        if (extraQuery is not null)
        {
            foreach (var (key, value) in extraQuery)
            {
                query += $"&{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}";
            }
        }

        var result = await http.GetFromJsonAsync<PagedResult<TDto>>(query);
        return result ?? new PagedResult<TDto>([], 0, 1, 1);
    }

    public async Task<TDto?> GetOneAsync(string id)
    {
        return await http.GetFromJsonAsync<TDto>($"{ApiResourceName}/{id}");
    }

    public async Task<TDto> AddAsync(TDto movie)
    {
        var response = await http.PostAsJsonAsync($"{ApiResourceName}", movie);
        if (response.IsSuccessStatusCode)
        {
            return (await response.Content.ReadFromJsonAsync<TDto>())!;
        }

        // the API returns error bodies (free-tier quota 403s, ApiExceptionFilterAttribute's 400s/500s) -
        // surfacing that text beats EnsureSuccessStatusCode's opaque "403 (Forbidden)" in the Add form
        var body = await response.Content.ReadFromJsonAsync<ApiError>();
        throw new InvalidOperationException(string.IsNullOrEmpty(body?.Error)
            ? $"The request failed ({(int)response.StatusCode})."
            : body.Error);

    }

    public async Task UpdateAsync(TDto movie)
    {
        (await http.PutAsJsonAsync($"{ApiResourceName}/{movie.Id}", movie)).EnsureSuccessStatusCode();
    }

    public async Task DeleteAsync(string id)
    {
        (await http.DeleteAsync($"{ApiResourceName}/{id}")).EnsureSuccessStatusCode();
    }

    /// <summary>
    /// User-triggered, exact-match-only re-check against the local reference collection (POST api/{type}/{id}/refresh-reference on WebApi).
    /// Returns the (possibly now-linked) item so the caller can tell whether a match was actually found.
    /// </summary>
    public async Task<TDto> RefreshReferenceAsync(string id)
    {
        if (!hasReference)
        {
            throw new NotImplementedException();
        }

        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TDto>())!;
    }

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document (POST api/{type}/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<TDto> UnlinkReferenceAsync(string id)
    {
        if (!hasReference)
        {
            throw new NotImplementedException();
        }

        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TDto>())!;
    }
}
