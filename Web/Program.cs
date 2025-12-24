using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.HttpOverrides;
using Web.Data;
using Web.Models;
using Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Persist DataProtection keys on Azure App Service (prevents auth cookies becoming unreadable across restarts/instances)
// On Azure Linux, HOME is typically /home and is the durable, shared volume for the app.
var home = Environment.GetEnvironmentVariable("HOME");
if (!string.IsNullOrWhiteSpace(home))
{
    var keysDir = new DirectoryInfo(Path.Combine(home, "data-protection-keys"));
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(keysDir)
        .SetApplicationName("StudyChat");
}

// Add DbContext with PostgreSQL provider
// Connection string is loaded from:
// 1. Environment variable: ConnectionStrings__DefaultConnection (highest priority - Azure App Settings)
// 2. User Secrets (Development only): ConnectionStrings:DefaultConnection
// 3. appsettings.json: ConnectionStrings:DefaultConnection (lowest priority, not recommended for secrets)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Use placeholder during build if connection string is not available
    // This allows the app to build without secrets present
    var connString = connectionString ?? "Host=localhost;Database=placeholder;Username=placeholder;Password=placeholder";
    options.UseNpgsql(connString);
});

// MIGRATION INSTRUCTIONS (run these commands in the Web directory):
// 1. Create initial migration:
//    dotnet ef migrations add Init
//
// 2. Apply migrations to database:
//    dotnet ef database update
//
// Note: If tables already exist in the database, you may need to use:
//    dotnet ef migrations add Init --force
//    dotnet ef database update
//
// See DATABASE_SETUP.md for detailed instructions and connection string configuration.
// Triggering workflow rerun

// Register services
builder.Services.AddScoped<IStudentService, StudentService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<ChatService>();

// ============================================
// AUTHENTICATION CONFIGURATION
// ============================================
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    // Challenge unauthenticated users to the login page by default.
    // Google is still available via explicit Challenge("Google") on the relevant endpoints.
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/Login";
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
    
    // Cookie security settings for production
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Requires HTTPS
    options.Cookie.SameSite = SameSiteMode.Lax; // Allows OAuth redirects
})
.AddGoogle("Google", options =>
{
    // Read from configuration (Azure App Settings: Google__ClientId, Google__ClientSecret)
    // Or User Secrets (Development): Google:ClientId, Google:ClientSecret
    // Note: Validation happens at runtime, not during build
    var clientId = builder.Configuration["Google:ClientId"];
    var clientSecret = builder.Configuration["Google:ClientSecret"];

    // Allow null during build - validation happens at runtime
    options.ClientId = clientId ?? string.Empty;
    options.ClientSecret = clientSecret ?? string.Empty;
    
    // Callback path (must match Google Cloud Console: /signin-google)
    // Google Cloud Console: https://studychat-bcd3a5hmgqcvgvam.francecentral-01.azurewebsites.net/signin-google
    options.CallbackPath = "/signin-google";
    options.SaveTokens = true;
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    
    // Request additional scopes
    options.Scope.Add("email");
    options.Scope.Add("profile");
    
    // Note: In .NET 9.0, Google OAuth automatically maps standard claims:
    // - "sub" -> ClaimTypes.NameIdentifier
    // - "email" -> ClaimTypes.Email  
    // - "name" -> ClaimTypes.Name
    // Additional claims like "picture" can be accessed directly in the callback handler
    
    // Handle authentication directly when ticket is received
    options.Events.OnCreatingTicket = async context =>
    {
        // This event fires when Google authentication succeeds
        // We'll handle user creation and cookie sign-in here
        // The RedirectUri will be used after this event completes
    };

    // Harden correlation cookie behavior for modern browsers + reverse proxies.
    // If the app thinks requests are HTTP (misconfigured forwarded headers), SameSite=None cookies without Secure
    // will be rejected by browsers, causing "Correlation failed".
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.CorrelationCookie.HttpOnly = true;

    // Handle remote auth failures (correlation/state/config issues, user denied consent, etc.)
    options.Events.OnRemoteFailure = context =>
    {
        var serviceProvider = context.HttpContext.RequestServices;
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        var traceId = context.HttpContext.TraceIdentifier;

        logger.LogError(context.Failure, "Google remote authentication failed. TraceId={TraceId}", traceId);

        var msg = context.Failure?.Message ?? "Google authentication failed";
        var redirect = $"/Account/Login?error={Uri.EscapeDataString($"{msg} (Ref: {traceId})")}";
        context.Response.Redirect(redirect);
        context.HandleResponse();
        return Task.CompletedTask;
    };
    
    // Handle after ticket is created - this is where we process the user
    options.Events.OnTicketReceived = async context =>
    {
        // Get the service provider to access UserService
        var serviceProvider = context.HttpContext.RequestServices;
        var userService = serviceProvider.GetRequiredService<UserService>();
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

        var flow = context.Properties?.Items.TryGetValue("flow", out var f) == true ? f : null;
        
        try
        {
            // "register" flow: do NOT touch DB / do NOT replace principal.
            // The controller callback will handle "create if not exists" and then redirect to Login.
            if (string.Equals(flow, "register", StringComparison.OrdinalIgnoreCase))
            {
                logger.LogInformation("Google auth flow=register; skipping DB upsert and principal replacement. RedirectUri={RedirectUri}", context.Properties?.RedirectUri);
                return;
            }

            // Extract Google claims
            var claims = context.Principal?.Claims;
            if (claims == null)
            {
                logger.LogWarning("No claims received from Google");
                context.Fail("No claims received from Google");
                return;
            }

            var googleSub = claims.FirstOrDefault(c => c.Type == "sub" || c.Type == ClaimTypes.NameIdentifier)?.Value;
            var email = claims.FirstOrDefault(c => c.Type == "email" || c.Type == ClaimTypes.Email)?.Value;
            var name = claims.FirstOrDefault(c => c.Type == "name" || c.Type == ClaimTypes.Name)?.Value;

            if (string.IsNullOrEmpty(googleSub) || string.IsNullOrEmpty(email))
            {
                logger.LogWarning("Missing required Google claims: sub={Sub}, email={Email}", googleSub, email);
                context.Fail("Missing required Google claims");
                return;
            }

            // Upsert user in database
            logger.LogInformation("Attempting to upsert user: Email={Email}, GoogleSub={GoogleSub}", email, googleSub);
            User user;
            try
            {
                user = await userService.UpsertGoogleUserAsync(googleSub, email, name);
                logger.LogInformation("User upserted successfully: UserId={UserId}, Email={Email}", user.Id, user.Email);
            }
            catch (Exception dbEx)
            {
                logger.LogError(dbEx, "Database error while upserting user: {Message}", dbEx.Message);
                context.Fail($"Database error: {dbEx.Message}");
                return;
            }

            // Create local claims for cookie authentication
            var localClaims = new List<Claim>
            {
                new Claim("studychat_user_id", user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.FullName ?? user.Email ?? string.Empty)
            };

            var claimsIdentity = new ClaimsIdentity(localClaims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            
            // Replace the principal in the context so the authentication middleware recognizes the user
            context.Principal = claimsPrincipal;
            
            // Let the Google handler issue the cookie using our principal + properties.
            context.Properties.IsPersistent = true;
            context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30);
            context.Properties.AllowRefresh = true;
            
            // Don't force a return path here. We honor the RedirectUri set in /Account/GoogleLogin,
            // which routes through /Account/GoogleCallback (and preserves any returnUrl).
            logger.LogInformation(
                "Google authentication successful; upserted user and established cookie principal. Email={Email}, UserId={UserId}, RedirectUri={RedirectUri}",
                email,
                user.Id,
                context.Properties?.RedirectUri);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing Google authentication");
            context.Fail($"Error processing authentication: {ex.Message}");
        }
    };
});

var app = builder.Build();

// ============================================
// RUNTIME CONFIGURATION VALIDATION
// ============================================
// Validate required configuration at runtime (not during build)
// This allows the app to build without secrets, but fail fast at startup if missing
// Re-read connection string at runtime (it was read earlier for DbContext setup)
var runtimeConnectionString = app.Configuration.GetConnectionString("DefaultConnection");
var googleClientId = app.Configuration["Google:ClientId"];
var googleClientSecret = app.Configuration["Google:ClientSecret"];

var missingConfig = new List<string>();
if (string.IsNullOrWhiteSpace(runtimeConnectionString))
{
    missingConfig.Add("ConnectionStrings:DefaultConnection (Azure: ConnectionStrings__DefaultConnection)");
}
if (string.IsNullOrWhiteSpace(googleClientId))
{
    missingConfig.Add("Google:ClientId (Azure: Google__ClientId)");
}
if (string.IsNullOrWhiteSpace(googleClientSecret))
{
    missingConfig.Add("Google:ClientSecret (Azure: Google__ClientSecret)");
}

// Get logger factory for validation logging
var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
var startupLogger = loggerFactory.CreateLogger("Startup");

if (missingConfig.Any())
{
    var errorMessage = $"CRITICAL: Missing required configuration values:\n" +
                       string.Join("\n", missingConfig.Select(c => $"  - {c}")) +
                       "\n\nPlease configure these in Azure App Settings or User Secrets.";
    
    startupLogger.LogError(errorMessage);
    throw new InvalidOperationException(errorMessage);
}

// Log validation success (without secrets)
startupLogger.LogInformation("Configuration validation passed. All required settings are present.");
startupLogger.LogInformation("Database connection: CONFIGURED");
startupLogger.LogInformation("Google OAuth: CONFIGURED");

// ============================================
// DATABASE INITIALIZATION (NO MIGRATIONS IN REPO)
// ============================================
// This project currently has no EF Core migrations committed. In that case, a fresh database will not
// have the required tables (users/chats/messages/...) and the StudyChat page will crash with a 500.
// EnsureCreated() will create the schema from the current model if it doesn't exist.
try
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var created = await db.Database.EnsureCreatedAsync();
    startupLogger.LogInformation("Database EnsureCreated completed. CreatedNewSchema={Created}", created);
}
catch (Exception ex)
{
    startupLogger.LogError(ex, "Database initialization failed (EnsureCreated). The app may not function correctly until the database is reachable and initialized.");
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    // Do not redirect all server errors to the login page (it hides real 500s and looks like auth failed).
    // Send users to a real error page with a RequestId so we can debug production issues.
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// Ensure correct scheme/host behind Azure reverse proxy
// IMPORTANT: Azure App Service is a reverse proxy. If we don't correctly process X-Forwarded-* headers,
// the app will think requests are HTTP (not HTTPS), which can break OAuth correlation cookies and auth flows.
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
    // Azure can chain proxies; don't artificially limit forwarded header processing.
    ForwardLimit = null,
};
// Clear the default "trust only loopback proxies" restriction so Azure's proxy headers are honored.
forwardedHeadersOptions.KnownNetworks.Clear();
forwardedHeadersOptions.KnownProxies.Clear();
app.UseForwardedHeaders(forwardedHeadersOptions);

app.UseHttpsRedirection();
app.UseRouting();

// Authentication & Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

// Map routes without requiring authorization (authorization is handled per-controller/action)
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}")
    .WithStaticAssets();

// Add explicit route for StudyChat to ensure it works
app.MapControllerRoute(
    name: "studychat",
    pattern: "StudyChat/{action=Index}/{id?}",
    defaults: new { controller = "StudyChat", action = "Index" })
    .WithStaticAssets()
    .RequireAuthorization();

app.Run();
