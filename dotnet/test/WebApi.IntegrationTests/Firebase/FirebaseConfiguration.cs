using System;

namespace KeepTrack.WebApi.IntegrationTests.Firebase;

public class FirebaseConfiguration
{
    public static string? ApplicationKey => Environment.GetEnvironmentVariable("Firebase__Application__Key");

    public static string? Username => Environment.GetEnvironmentVariable("Firebase__Username");

    public static string? Password => Environment.GetEnvironmentVariable("Firebase__Password");
}
