using authserver.Seeders;
using authserver.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;

//https://legimenes.medium.com/authorization-server-with-openiddict-the-serie-e2721d0451af
//https://documentation.openiddict.com/guides/getting-started/creating-your-own-server-instance
//https://medium.com/@sergeygoodgood/openid-connect-and-oauth2-0-server-in-aspnetcore-using-openiddict-c463c6ebc082
//https://dev.to/mohammedahmed/build-your-own-oauth-20-server-and-openid-connect-provider-in-aspnet-core-60-1g1m
//https://www.oauth.com

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<DbContext>(options =>
{
    options.UseInMemoryDatabase(nameof(DbContext));
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<DbContext>();
    })
    .AddServer(options =>
    {
        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .RequireProofKeyForCodeExchange();
        options
            .SetAuthorizationEndpointUris("/api/connect/authorize")
            .SetTokenEndpointUris("/api/connect/token")
            .SetUserinfoEndpointUris("/api/connect/userinfo")
            .SetLogoutEndpointUris("/api/connect/logout");

        options.AddEncryptionKey(new SymmetricSecurityKey(
            Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);
        //secret registration
        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate()
            ;

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            ;
    })
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // access duration for particular cookie
        options.LoginPath = "/api/login"; // Redirect for unauthorized requests
        //options.AccessDeniedPath = "/account/accessdenied";
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        };
    });

builder.Services.AddHostedService<ClientSeeder>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins",
        builder =>
        {
            builder
            .WithOrigins("http://localhost:3000")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
        });
});

builder.Services.AddControllers(options =>
{
    options.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true;
});


builder.Services.AddSwaggerGen();

builder.Services.AddScoped<UserService>();

var app = builder.Build();
app.UseDeveloperExceptionPage();

app.UseCors("AllowSpecificOrigins");

app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();

app.MapControllers();

app.UseAuthentication();
app.UseAuthorization();

app.UseHttpsRedirection();


app.Run();
