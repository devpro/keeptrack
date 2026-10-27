using System.Net;
using System.Threading;
using Keeptrack.BlazorApp.Components.Shared;
using Keeptrack.Common.System;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public abstract class InventoryApiClientBase<TDto>(HttpClient http, bool hasReference = false)
    where TDto : IHasId
{
    private sealed record ApiError(string? Error);

    protected abstract string ApiResourceName { get; }

    /// <summary>
    /// Exposes the HttpClient to subclasses adding their own calls, rather than each capturing its own primary-constructor parameter as a second field holding the same reference.
    /// </summary>
    protected HttpClient Http => http;

    // An id comes from the page route, so unescaped "../admin" would address another API resource.
    private string ItemPath(string? id) => $"{ApiResourceName}/{Uri.EscapeDataString(id ?? string.Empty)}";

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
    /// Returns null when the API reports 404: an id that doesn't exist, or one belonging to another owner, indistinguishable by design since every query is owner-scoped.
    /// Every detail page renders its "&lt;type&gt; not found." state from that null.
    /// <c>GetFromJsonAsync</c> would throw on the 404, killing the circuit on an in-app navigation, or sending the prerender to the generic /error page on a direct load.
    /// Any other failure throws, since only "it isn't there" is an expected answer.
    /// </summary>
    public async Task<TDto?> GetOneAsync(string id, CancellationToken cancellationToken = default)
    {
        var response = await http.GetAsync(ItemPath(id), cancellationToken);
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

        // The API returns error bodies (free-tier quota 403s, ApiExceptionFilterAttribute's 400s and 500s).
        // Their text beats EnsureSuccessStatusCode's opaque "403 (Forbidden)" in the Add form.
        var body = await response.Content.ReadFromJsonAsync<ApiError>(cancellationToken);
        throw new InvalidOperationException(string.IsNullOrEmpty(body?.Error)
            ? $"The request failed ({(int)response.StatusCode})."
            : body.Error);

    }

    public async Task UpdateAsync(TDto movie, CancellationToken cancellationToken = default)
    {
        (await http.PutAsJsonAsync(ItemPath(movie.Id), movie, cancellationToken)).EnsureSuccessStatusCode();
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        (await http.DeleteAsync(ItemPath(id), cancellationToken)).EnsureSuccessStatusCode();
    }

    /// <summary>
    /// User-triggered re-check of the item's reference match (POST api/{type}/{id}/refresh-reference on WebApi), escalating to the provider when nothing local matches.
    /// Returns the item, linked or not, so the caller can tell whether a match was found,
    /// and throws <see cref="ApiRequestException"/> with the API's own message, which the page shows.
    /// </summary>
    public async Task<TDto> RefreshReferenceAsync(string id, CancellationToken cancellationToken = default)
    {
        if (!hasReference)
        {
            throw new NotImplementedException();
        }

        var response = await Http.PostAsync($"{ItemPath(id)}/refresh-reference", null, cancellationToken);
        return (await response.ReadJsonOrThrowAsync<TDto>(cancellationToken))!;
    }

    /// <summary>
    /// For admins: unlinks and permanently deletes the shared reference document (POST api/{type}/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<TDto> UnlinkReferenceAsync(string id, CancellationToken cancellationToken = default)
    {
        if (!hasReference)
        {
            throw new NotImplementedException();
        }

        var response = await Http.PostAsync($"{ItemPath(id)}/unlink-reference", null, cancellationToken);
        return (await response.ReadJsonOrThrowAsync<TDto>(cancellationToken))!;
    }
}
