using System.Net.Http.Json;
using Keeptrack.BlazorApp.Components.Shared;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

/// <summary>
/// The shared, owner-less fuel-station catalogue.
/// Not an <see cref="InventoryApiClientBase{TDto}"/>, whose whole surface is owner-scoped paged CRUD, which this collection isn't.
/// </summary>
public sealed class CarStationApiClient(HttpClient http)
{
    private const string ApiResourceName = "/api/car-stations";

    public async Task<List<CarStationDto>> GetAllAsync()
    {
        var response = await http.GetAsync(ApiResourceName);
        return await response.ReadJsonOrThrowAsync<List<CarStationDto>>() ?? [];
    }

    /// <summary>The catalogue with each station's usage count, for admins only.</summary>
    public async Task<List<CarStationDto>> GetForAdminAsync()
    {
        var response = await http.GetAsync($"{ApiResourceName}/admin");
        return await response.ReadJsonOrThrowAsync<List<CarStationDto>>() ?? [];
    }

    /// <summary>
    /// Find-or-create by natural key: posting a station the catalogue holds returns it rather than a duplicate, which lets the picker create freely.
    /// </summary>
    public async Task<CarStationDto?> FindOrCreateAsync(CarStationDto station)
    {
        var response = await http.PostAsJsonAsync(ApiResourceName, station);
        return await response.ReadJsonOrThrowAsync<CarStationDto>();
    }

    public async Task UpdateAsync(CarStationDto station)
    {
        var response = await http.PutAsJsonAsync($"{ApiResourceName}/{station.Id}", station);
        await response.EnsureSuccessOrThrowAsync();
    }

    public async Task DeleteAsync(string id)
    {
        var response = await http.DeleteAsync($"{ApiResourceName}/{id}");
        await response.EnsureSuccessOrThrowAsync();
    }

    public async Task<CarStationMergeResultDto?> MergeAsync(string id, string targetId)
    {
        var response = await http.PostAsync($"{ApiResourceName}/{id}/merge/{targetId}", null);
        return await response.ReadJsonOrThrowAsync<CarStationMergeResultDto>();
    }
}
