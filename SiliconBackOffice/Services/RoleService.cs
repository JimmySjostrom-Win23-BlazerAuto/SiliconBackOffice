using Microsoft.AspNetCore.Components.Authorization;

namespace SiliconBackOffice.Services;

public class RoleService
{
    private readonly AuthenticationStateProvider _authenticationStateProvider;

    public RoleService(AuthenticationStateProvider authenticationStateProvider)
    {
        _authenticationStateProvider = authenticationStateProvider;
    }

    /// <summary>
    /// Async check if the current user is authenticated and has the "Manager" role.
    /// </summary>
    /// <returns>
    /// The task result returns a bool whether the current user is authenticated and 
    /// has the "Manager" role.
    /// </returns>
    public async Task<bool> IsManagerAsync()
    {
        var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;

        return user.Identity != null && user.Identity.IsAuthenticated && user.IsInRole("Manager");
    }
}