using System;

namespace KeepTrack.WebApi.IntegrationTests.Firebase;

public static class FirebaseConfiguration
{
    public static string ApplicationKey => GetEnvironmentVariable("FIREBASE_APIKEY");

    public static string Username => GetEnvironmentVariable("FIREBASE_USERNAME");

    public static string Password => GetEnvironmentVariable("FIREBASE_PASSWORD");

    private static string GetEnvironmentVariable(string name)
    {
        return Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process)
               ?? throw new InvalidOperationException($"Environment variable {name} was not found.");
    }
}
