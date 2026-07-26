using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

/// <summary>
/// <see cref="AmazonReference"/> is the read side of <see cref="AmazonImportMergeService.FormatOrderReference"/>'s
/// write side - covers both the round trip between them and the parts unique to the read side (vendor domain).
/// </summary>
[Trait("Category", "UnitTests")]
public class AmazonReferenceTest
{
    [Fact]
    public void TryExtractAsin_RoundTrips_WhatFormatOrderReferenceWrote()
    {
        var reference = AmazonImportMergeService.FormatOrderReference("405-1111111-1111111", "0552177571");

        AmazonReference.TryExtractAsin(reference).Should().Be("0552177571");
    }

    [Fact]
    public void TryExtractAsin_ReturnsNull_ForAManuallyEnteredReferenceWithNoAsin()
    {
        AmazonReference.TryExtractAsin("Special edition, box 3").Should().BeNull();
    }

    [Fact]
    public void TryExtractAsin_ReturnsNull_ForNullOrEmptyReference()
    {
        AmazonReference.TryExtractAsin(null).Should().BeNull();
        AmazonReference.TryExtractAsin("").Should().BeNull();
    }

    [Fact]
    public void BuildProductUrl_UsesTheVendorsOwnAmazonDomain_WhenItLooksLikeOne()
    {
        AmazonReference.BuildProductUrl("0552177571", "Amazon.fr").Should().Be("https://amazon.fr/dp/0552177571");
        AmazonReference.BuildProductUrl("0552177571", "www.amazon.de").Should().Be("https://www.amazon.de/dp/0552177571");
    }

    [Fact]
    public void BuildProductUrl_FallsBackToAmazonFr_WhenTheVendorIsntRecognizablyAmazon()
    {
        AmazonReference.BuildProductUrl("0552177571", "Fnac").Should().Be("https://www.amazon.fr/dp/0552177571");
        AmazonReference.BuildProductUrl("0552177571", null).Should().Be("https://www.amazon.fr/dp/0552177571");
    }
}
