using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Houses : InventoryPageBase<HouseDto>
{
    [Inject] private HouseApiClient HouseApi { get; set; } = null!;

    protected override InventoryApiClientBase<HouseDto> Api => HouseApi;

    protected override string ListRoute => "/houses";

    protected override HouseDto CloneItem(HouseDto item) => new()
    {
        Id = item.Id,
        Name = item.Name,
        Address = item.Address,
        City = item.City,
        PostalCode = item.PostalCode,
        Country = item.Country,
        Notes = item.Notes
    };
}
