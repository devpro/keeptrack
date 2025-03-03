using System.Security.Claims;
using Blazored.LocalStorage;
using KeepTrack.BlazorWebAssemblyApp.Models;
using Microsoft.AspNetCore.Components.Authorization;

namespace KeepTrack.BlazorWebAssemblyApp.Authorization
{
    public class ExternalAuthStateProvider(ILogger<ExternalAuthStateProvider> logger, ILocalStorageService localStorage) : AuthenticationStateProvider
    {
        private readonly ILogger<ExternalAuthStateProvider> _logger = logger;

        private readonly ILocalStorageService _localStorage = localStorage;

        private UserModel? _userModel;

        public async Task UpdateAuthentitationStateAsync(string displayName, string emailAddress, string token)
        {
            _userModel = new UserModel { DisplayName = displayName, EmailAddress = emailAddress, Token = token };
            await _localStorage.SetItemAsync("user", _userModel);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (string.IsNullOrEmpty(_userModel?.DisplayName))
            {
                _userModel = await _localStorage.GetItemAsync<UserModel>("user");
            }

            if (string.IsNullOrEmpty(_userModel?.DisplayName))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var identity = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, _userModel.DisplayName),
                    new Claim(ClaimTypes.Email, _userModel.EmailAddress),
                    new Claim("Token", _userModel.Token)
                ],
                "Federated authentication");

            _logger.LogInformation($"{nameof(GetAuthenticationStateAsync)} called at {DateTime.Now.ToLongTimeString()}");

            var user = new ClaimsPrincipal(identity);

            return new AuthenticationState(user);
        }
    }
}
