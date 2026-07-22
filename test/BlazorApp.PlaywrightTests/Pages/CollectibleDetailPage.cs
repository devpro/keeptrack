using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Collectibles have no reference-data concept, same as <see cref="CarDetailPage"/> - a plain <see cref="DetailPageBase"/>.
/// </summary>
public class CollectibleDetailPage(IPage page) : DetailPageBase(page);
