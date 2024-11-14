using Microsoft.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Collections.Immutable;
using System.Security.Principal;
using XAct.Users;
using Microsoft.AspNetCore.Http.HttpResults;
using Amazon.Auth.AccessControlPolicy;
using System.Net;

namespace authserver.Controllers
{
    [Route("api")]
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        public AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager, IOpenIddictAuthorizationManager authorizationManager)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _authorizationManager = authorizationManager;
        }

        [HttpPost("connect/token"), Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");


            ClaimsPrincipal claimsPrincipal;
            claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("connect/authorize")]
        [HttpGet("connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest() ??
                            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            AuthenticateResult result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            Console.WriteLine(result.Succeeded);
            if (!result.Succeeded)
            {
                return Challenge(
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                    });
            }

            var userEmail = result.Principal.GetClaim(Claims.Subject);
            var userName = result.Principal.GetClaim(Claims.Name);
            var userRoles = result.Principal.GetClaim(Claims.Role);

            Console.WriteLine(userEmail);
            Console.WriteLine(userName);
            Console.WriteLine(userRoles);

            var claimsIdentity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role
            );

            claimsIdentity.SetClaim(Claims.Subject, userEmail)
                     .SetClaim(Claims.Email, userEmail)
                     .SetClaim(Claims.Name, userName)
                     .SetClaims(Claims.Role, userRoles.Split(" ").ToImmutableArray()); ;

            // Set requested scopes (this is not done automatically)
            claimsIdentity.SetResources(await _scopeManager.ListResourcesAsync(claimsIdentity.GetScopes()).ToListAsync());
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            claimsPrincipal.SetScopes(request.GetScopes());
            claimsPrincipal.SetResources(await _scopeManager.ListResourcesAsync(claimsPrincipal.GetScopes()).ToListAsync());
            claimsPrincipal.SetDestinations(static claim => claim.Type switch
            {
                // If the "profile" scope was granted, allow the "name" claim to be
                // added to the access and identity tokens derived from the principal.
                Claims.Name when claim.Subject.HasScope(Scopes.Profile) =>
                [
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                ],
                Claims.Email when claim.Subject.HasScope(Scopes.Profile) =>
                [
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                ],
                Claims.Role when claim.Subject.HasScope(Scopes.Profile) =>
                [
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                ],
                // Otherwise, add the claim to the access tokens only.
                _ => [OpenIddictConstants.Destinations.AccessToken]
            });
            Console.WriteLine("END AUTHORIZEEE");
            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
            foreach (var claim in claimsPrincipal.Claims)
            {
                Console.WriteLine($"Claim Type: {claim.Type}, Claim Value: {claim.Value}");
            }
            return Ok(new
            {
                Sub = claimsPrincipal.GetClaim(Claims.Subject),
                Name = claimsPrincipal.GetClaim(Claims.Name),
                Roles = claimsPrincipal.GetClaims(Claims.Role).ToString(),
                Email = claimsPrincipal.GetClaim(Claims.Email)
            });
        }


        [HttpGet("connect/logout")]
        [HttpPost("connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                  authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                  properties: new AuthenticationProperties
                  {
                      RedirectUri = "/"
                  });
        }


    }
}
