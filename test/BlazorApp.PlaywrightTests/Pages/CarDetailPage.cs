using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Cars have no reference-data concept (confirmed: no <c>ReferenceId</c> on <c>CarDto</c>, no
/// <c>InlineReferenceLinker</c> in <c>CarDetail.razor</c>), so this is a plain <see cref="DetailPageBase"/>.
/// </summary>
public class CarDetailPage(IPage page) : DetailPageBase(page);
