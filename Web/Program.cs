using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.HttpOverrides;
using Npgsql;
using Web.Data;
using Web.Models;
using Web.Services;
using Web.Middleware;
using Web.Extensions;

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
    
    // Optimize connection string for Azure/Supabase performance
    // Build optimized connection string with pooling parameters
    var connBuilder = new NpgsqlConnectionStringBuilder(connString);
    
    // Connection pooling settings for better performance
    connBuilder.Pooling = true;
    connBuilder.MinPoolSize = 5; // Keep minimum connections ready
    connBuilder.MaxPoolSize = 100; // Allow up to 100 concurrent connections
    connBuilder.ConnectionLifetime = 0; // Don't recycle connections (0 = disabled)
    connBuilder.Timeout = 15; // Connection timeout in seconds (reduced from default 30)
    connBuilder.CommandTimeout = 15; // Command timeout in seconds
    
    // Additional performance optimizations
    connBuilder.NoResetOnClose = true; // Don't reset connection state on close (faster)
    connBuilder.TcpKeepAlive = true; // Keep connections alive
    
    options.UseNpgsql(connBuilder.ConnectionString, npgsqlOptions =>
    {
        // Enable retry on transient failures (reduced retries for faster failure detection)
        npgsqlOptions.EnableRetryOnFailure(
            maxRetryCount: 2, // Reduced from 3 to 2 for faster failure
            maxRetryDelay: TimeSpan.FromSeconds(2), // Reduced from 5 to 2 seconds
            errorCodesToAdd: null);
        // Command timeout is set in connection string, but also set here for consistency
        npgsqlOptions.CommandTimeout(15);
    });
    // Enable sensitive data logging in development only
    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
    }
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
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<ChatService>();

// Register HttpClient for AI webhook calls
// Configure to handle self-signed certificates (for testing webhooks with self-signed certs)
// NOTE: This bypasses SSL validation - only use with trusted internal webhooks
builder.Services.AddHttpClient("AiWebhook", client =>
{
    client.Timeout = TimeSpan.FromSeconds(60);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    
    // Allow self-signed certificates for webhook (n8n typically uses self-signed certs)
    // This is needed because the webhook at https://20.19.81.149 has a self-signed certificate
    // WARNING: Only use this for trusted internal webhooks, not for external/public APIs
    handler.ServerCertificateCustomValidationCallback = 
        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    
    return handler;
});

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
            
            // Link session to user (update session with UserId) - do in background to avoid blocking OAuth flow
            // Use extension method to get session ID from HttpContext.Items or cookie
            var sessionId = context.HttpContext.GetSessionId();
            if (!string.IsNullOrEmpty(sessionId))
            {
                // Capture values before starting background task
                var capturedSessionId = sessionId;
                var capturedUserId = user.Id;
                var capturedServiceProvider = serviceProvider;
                
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var dbScope = capturedServiceProvider.CreateScope();
                        var dbContext = dbScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                        var backgroundLogger = dbScope.ServiceProvider.GetService<ILogger<Program>>();
                        
                        var session = await dbContext.Sessions
                            .FirstOrDefaultAsync(s => s.SessionId == capturedSessionId);
                        
                        if (session != null)
                        {
                            session.UserId = capturedUserId;
                            session.LastAccessedAt = DateTimeOffset.UtcNow;
                            await dbContext.SaveChangesAsync();
                            backgroundLogger?.LogInformation("Linked session {SessionId} to user {UserId} during Google auth", capturedSessionId, capturedUserId);
                        }
                        else
                        {
                            backgroundLogger?.LogWarning("Session {SessionId} not found in database during Google auth linking", capturedSessionId);
                        }
                    }
                    catch (Exception sessionEx)
                    {
                        // Log but don't fail - session linking is not critical
                        try
                        {
                            using var errorScope = capturedServiceProvider.CreateScope();
                            var errorLogger = errorScope.ServiceProvider.GetService<ILogger<Program>>();
                            errorLogger?.LogError(sessionEx, "Failed to link session {SessionId} to user {UserId} during Google auth", capturedSessionId, capturedUserId);
                        }
                        catch { }
                    }
                });
            }
            else
            {
                logger.LogWarning("No session ID found in HttpContext during Google auth. UserId={UserId}", user.Id);
            }
            
            // Let the Google handler issue the cookie using our principal + properties.
            if (context.Properties != null)
            {
                context.Properties.IsPersistent = true;
                context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30);
                context.Properties.AllowRefresh = true;
            }
            
            // IMPORTANT: Explicitly sign in the user here to ensure the cookie is set
            // This ensures the user is authenticated even if the redirect happens before background tasks complete
            try
            {
                await context.HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    claimsPrincipal,
                    context.Properties ?? new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30),
                        AllowRefresh = true
                    });
                logger.LogInformation("Explicitly signed in user {UserId} via cookie during Google auth", user.Id);
            }
            catch (Exception signInEx)
            {
                logger.LogWarning(signInEx, "Failed to explicitly sign in user during Google auth, but principal is set");
                // Don't fail - the principal is already set, cookie auth middleware should handle it
            }
            
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

// Session ID middleware - creates session ID cookie for first-time visitors
app.UseMiddleware<SessionIdMiddleware>();

app.UseHttpsRedirection();
app.UseRouting();

// Authentication & Authorization middleware - MUST run BEFORE SessionAuthenticationMiddleware
// This ensures cookie authentication populates context.User first, avoiding unnecessary DB queries
app.UseAuthentication();
app.UseAuthorization();

// Session-based authentication middleware - authenticates user based on session ID
// Runs AFTER cookie auth, so it only queries DB if user is not already authenticated
app.UseMiddleware<SessionAuthenticationMiddleware>();

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
