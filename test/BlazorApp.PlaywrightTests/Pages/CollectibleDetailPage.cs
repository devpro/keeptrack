using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Collectibles have no reference data, like <see cref="CarDetailPage"/>, so a plain <see cref="DetailPageBase"/>.
/// </summary>
public class CollectibleDetailPage(IPage page) : DetailPageBase(page);
