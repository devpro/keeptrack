using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Houses : InventoryPageBase<HouseDto>
{
    [Inject] private HouseApiClient HouseApi { get; set; } = null!;

    protected override InventoryApiClientBase<HouseDto> Api => HouseApi;

    protected override string ListRoute => "/houses";

    protected override string DefaultSort => ListSort.Title;
}
