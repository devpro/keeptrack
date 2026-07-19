using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Cars : InventoryPageBase<CarDto>
{
    [Inject] private CarApiClient CarApi { get; set; } = null!;

    protected override InventoryApiClientBase<CarDto> Api => CarApi;

    protected override string ListRoute => "/cars";

    protected override string DefaultSort => ListSort.Title;
}
