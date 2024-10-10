using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Polly;
using Microsoft.EntityFrameworkCore;

namespace authserver.Seeders
{
    public class ClientSeeder : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        public ClientSeeder(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            await PopulateInternalApps(scope, cancellationToken);
        }
        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        private async ValueTask PopulateInternalApps(IServiceScope scopeService, CancellationToken cancellationToken)
        {
            var context = scopeService.ServiceProvider.GetRequiredService<DbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            var manager = scopeService.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("postman", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "postman",
                    ClientSecret = "postman-secret",
                    DisplayName = "Postman",
                    RedirectUris = { new Uri("https://oauth.pstmn.io/v1/browser-callback") },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,

                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,

                        Permissions.Prefixes.Scope + "api",

                        Permissions.ResponseTypes.Code
                    }
                }, cancellationToken);
            }
        }
    }
}
