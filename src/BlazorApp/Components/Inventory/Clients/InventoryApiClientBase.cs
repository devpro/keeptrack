using Keeptrack.Common.System;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public abstract class InventoryApiClientBase<TDto>(HttpClient http)
    where TDto : IHasId
{
    protected abstract string ApiResourceName { get; }

    /// <summary>
    /// Exposes the HttpClient to subclasses that add their own calls (e.g. a refresh-reference endpoint) -
    /// lets them reuse this instance instead of capturing their own <c>HttpClient</c> primary-constructor
    /// parameter as a second field holding the same reference.
    /// </summary>
    protected HttpClient Http => http;

    public async Task<PagedResult<TDto>> GetAsync(string search, int page, int pageSize, IReadOnlyDictionary<string, string>? extraQuery = null)
    {
        var query = $"{ApiResourceName}?search={Uri.EscapeDataString(search)}&page={page}&pageSize={pageSize}";
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
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TDto>())!;
    }

    public async Task UpdateAsync(TDto movie)
    {
        (await http.PutAsJsonAsync($"{ApiResourceName}/{movie.Id}", movie)).EnsureSuccessStatusCode();
    }

    public async Task DeleteAsync(string id)
    {
        (await http.DeleteAsync($"{ApiResourceName}/{id}")).EnsureSuccessStatusCode();
    }
}
