using System;
using System.Text;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a minimal one-row Amazon order-history CSV for the import smoke test.
/// The row carries a real, checksum-valid ISBN-10 so it trips the "looks like a book" heuristic and is auto-selected as a Book,
/// and a per-call unique title plus a fresh order id so every run imports a genuinely new book the test then deletes -
/// never a dedup-hidden "already imported" row from a previous run.
/// Never use a real personal export as a fixture (same rule as the integration suite's own builders).
/// </summary>
internal static class AmazonImportFixtureCsvBuilder
{
    private const string BookIsbn = "0552177571";

    public static byte[] Build(string bookTitle)
    {
        var orderId = $"999-{Guid.NewGuid():N}";
        var csv = $"""
                   ASIN,Order Date,Order ID,Product Name,Product Condition,Total Amount,Website
                   {BookIsbn},2024-01-24T09:01:58Z,{orderId},{bookTitle},New,10.49,Amazon.fr

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
