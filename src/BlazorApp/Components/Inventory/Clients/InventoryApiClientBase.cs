using KeepTrack.Common.System;

namespace KeepTrack.BlazorApp.Components.Inventory.Clients;

public abstract class InventoryApiClientBase<TDto>(HttpClient http)
    where TDto : IHasId
{
    protected abstract string ApiResourceName { get; }

    public async Task<PagedResult<TDto>> GetAsync(string search, int page, int pageSize)
    {
        var query = $"{ApiResourceName}?search={Uri.EscapeDataString(search)}&page={page}&pageSize={pageSize}";
        var result = await http.GetFromJsonAsync<PagedResult<TDto>>(query);
        return result ?? new PagedResult<TDto>([], 0, 1, 1);
    }

    public async Task<TDto?> GetOneAsync(string id)
    {
        return await http.GetFromJsonAsync<TDto>($"{ApiResourceName}/{id}");
    }

    public async Task AddAsync(TDto movie)
    {
        (await http.PostAsJsonAsync($"{ApiResourceName}", movie)).EnsureSuccessStatusCode();
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
