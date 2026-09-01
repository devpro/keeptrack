using System.Net;
using System.Threading;
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

    public async Task<PagedResult<TDto>> GetAsync(string search, int page, int pageSize, IReadOnlyDictionary<string, string>? extraQuery = null, string? sort = null, CancellationToken cancellationToken = default)
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

        var result = await http.GetFromJsonAsync<PagedResult<TDto>>(query, cancellationToken);
        return result ?? new PagedResult<TDto>([], 0, 1, 1);
    }

    /// <summary>
    /// Returns null when the API reports 404 - an id that doesn't exist, or one belonging to another owner
    /// (every query is owner-scoped server-side, so the two are indistinguishable from here, deliberately).
    /// Every detail page already renders its own "&lt;type&gt; not found." state from that null; this used to call
    /// <c>GetFromJsonAsync</c>, whose built-in <c>EnsureSuccessStatusCode</c> made an ordinary 404 throw instead -
    /// killing the circuit on an in-app navigation, and blowing up the prerender pass into the generic /error
    /// page on a direct load, which left that null branch unreachable.
    /// Any other failure still throws: only "it isn't there" is an expected answer.
    /// </summary>
    public async Task<TDto?> GetOneAsync(string id, CancellationToken cancellationToken = default)
    {
        var response = await http.GetAsync($"{ApiResourceName}/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return default;
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<TDto>(cancellationToken);
    }

    public async Task<TDto> AddAsync(TDto movie, CancellationToken cancellationToken = default)
    {
        var response = await http.PostAsJsonAsync($"{ApiResourceName}", movie, cancellationToken);
        if (response.IsSuccessStatusCode)
        {
            return (await response.Content.ReadFromJsonAsync<TDto>(cancellationToken))!;
        }

        // the API returns error bodies (free-tier quota 403s, ApiExceptionFilterAttribute's 400s/500s) -
        // surfacing that text beats EnsureSuccessStatusCode's opaque "403 (Forbidden)" in the Add form
        var body = await response.Content.ReadFromJsonAsync<ApiError>(cancellationToken);
        throw new InvalidOperationException(string.IsNullOrEmpty(body?.Error)
            ? $"The request failed ({(int)response.StatusCode})."
            : body.Error);

    }

    public async Task UpdateAsync(TDto movie, CancellationToken cancellationToken = default)
    {
        (await http.PutAsJsonAsync($"{ApiResourceName}/{movie.Id}", movie, cancellationToken)).EnsureSuccessStatusCode();
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        (await http.DeleteAsync($"{ApiResourceName}/{id}", cancellationToken)).EnsureSuccessStatusCode();
    }

    /// <summary>
    /// User-triggered, exact-match-only re-check against the local reference collection (POST api/{type}/{id}/refresh-reference on WebApi).
    /// Returns the (possibly now-linked) item so the caller can tell whether a match was actually found.
    /// </summary>
    public async Task<TDto> RefreshReferenceAsync(string id, CancellationToken cancellationToken = default)
    {
        if (!hasReference)
        {
            throw new NotImplementedException();
        }

        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null, cancellationToken);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TDto>(cancellationToken))!;
    }

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document (POST api/{type}/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<TDto> UnlinkReferenceAsync(string id, CancellationToken cancellationToken = default)
    {
        if (!hasReference)
        {
            throw new NotImplementedException();
        }

        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null, cancellationToken);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TDto>(cancellationToken))!;
    }
}
