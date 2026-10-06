using System;
using System.Text;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a minimal one-row Amazon order-history CSV for the import smoke test.
/// The row carries a real, checksum-valid ISBN-10, so the "looks like a book" heuristic selects it as a Book.
/// A per-call unique title and fresh order id make every run import a new book the test deletes, never an "already imported" row from a previous run.
/// A real personal export is never a fixture, as in the integration suite's builders.
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
