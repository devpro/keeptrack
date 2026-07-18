using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class HealthProfiles : InventoryPageBase<HealthProfileDto>
{
    [Inject] private HealthProfileApiClient HealthProfileApi { get; set; } = null!;

    protected override InventoryApiClientBase<HealthProfileDto> Api => HealthProfileApi;

    protected override string ListRoute => "/health";

    protected override string DefaultSort => ListSort.Title;
}
