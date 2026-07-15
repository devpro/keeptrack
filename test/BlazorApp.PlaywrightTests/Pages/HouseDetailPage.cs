using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Houses have no reference-data concept (confirmed: no <c>ReferenceId</c> on <c>HouseDto</c>, no
/// <c>InlineReferenceLinker</c> in <c>HouseDetail.razor</c>), so this is a plain <see cref="DetailPageBase"/>.
/// </summary>
public class HouseDetailPage(IPage page) : DetailPageBase(page);
