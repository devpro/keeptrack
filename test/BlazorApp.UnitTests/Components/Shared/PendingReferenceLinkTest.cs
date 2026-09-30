using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Shared;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>
/// The poll that shows a freshly created item's reference link once the server's background resolution lands.
/// Its stopping conditions are the whole of its behaviour: it must stop when the link arrives, stop when the page has changes of its own, and stop eventually either way - a re-read replaces the page's whole model, so one issued at the wrong moment puts the pre-edit item back on screen and back into the model.
/// </summary>
[Trait("Category", "UnitTests")]
public class PendingReferenceLinkTest
{
    [Fact]
    public async Task WatchAsync_ReadsNothing_WhenTheItemIsAlreadyLinked()
    {
        var reads = 0;

        await PendingReferenceLink.WatchAsync(() => true, () => Count(ref reads), NoRender, Unedited);

        reads.Should().Be(0);
    }

    [Fact]
    public async Task WatchAsync_StopsAsSoonAsTheLinkLands()
    {
        var reads = 0;
        var linked = false;

        await PendingReferenceLink.WatchAsync(
            () => linked,
            () =>
            {
                linked = true;
                return Count(ref reads);
            },
            NoRender,
            Unedited);

        reads.Should().Be(1);
    }

    /// <summary>
    /// The regression this guard exists for: a platform removed on a just-created game reappeared, with everything that had been set on it, because a poll issued before the save was answered after it.
    /// </summary>
    [Fact]
    public async Task WatchAsync_StopsReading_OnceThePageHasChangesOfItsOwn()
    {
        var reads = 0;
        var edited = false;

        await PendingReferenceLink.WatchAsync(
            () => false,
            () =>
            {
                edited = true; // the page saves something while the first poll is in flight
                return Count(ref reads);
            },
            NoRender,
            () => !edited);

        reads.Should().Be(1);
    }

    [Fact]
    public async Task WatchAsync_ReadsNothingAtAll_WhenThePageWasAlreadyEdited()
    {
        var reads = 0;

        await PendingReferenceLink.WatchAsync(() => false, () => Count(ref reads), NoRender, () => false);

        reads.Should().Be(0);
    }

    // The "no link ever lands" case is deliberately not tested here: it would sit through the whole attempt budget in real time (nine seconds) to assert a bound the for loop already guarantees by construction.

    private static Task Count(ref int reads)
    {
        reads++;
        return Task.CompletedTask;
    }

    private static Task NoRender() => Task.CompletedTask;

    private static bool Unedited() => true;
}
