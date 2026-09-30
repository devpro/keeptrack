using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class ShareCategoryClassifierTest
{
    [Theory]
    [InlineData(ShareCategory.Movies)]
    [InlineData(ShareCategory.TvShows)]
    [InlineData(ShareCategory.Books)]
    [InlineData(ShareCategory.Albums)]
    [InlineData(ShareCategory.VideoGames)]
    public void MediaCategories_AreMedia_AndCopyable(ShareCategory category)
    {
        ShareCategoryClassifier.KindOf(category).Should().Be(ShareKind.Media);
        ShareCategoryClassifier.IsCopyable(category).Should().BeTrue();
    }

    [Theory]
    [InlineData(ShareCategory.Collectibles)]
    [InlineData(ShareCategory.Gears)]
    public void CollectionCategories_AreCollection_AndNeverCopyable(ShareCategory category)
    {
        ShareCategoryClassifier.KindOf(category).Should().Be(ShareKind.Collection);
        ShareCategoryClassifier.IsCopyable(category).Should().BeFalse();
    }

    [Theory]
    [InlineData(ShareCategory.Cars)]
    [InlineData(ShareCategory.Houses)]
    [InlineData(ShareCategory.Health)]
    public void PersonalCategories_ArePersonal_AndNeverCopyable(ShareCategory category)
    {
        ShareCategoryClassifier.KindOf(category).Should().Be(ShareKind.Personal);
        ShareCategoryClassifier.IsCopyable(category).Should().BeFalse();
    }
}
