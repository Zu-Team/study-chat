using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Web.Data;
using Web.Models;
using Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

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
    options.DefaultChallengeScheme = "Google";
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
    
    // Handle after ticket is created - this is where we process the user
    options.Events.OnTicketReceived = async context =>
    {
        // Get the service provider to access UserService
        var serviceProvider = context.HttpContext.RequestServices;
        var userService = serviceProvider.GetRequiredService<UserService>();
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        
        try
        {
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
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.FullName ?? user.Email ?? string.Empty)
            };

            var claimsIdentity = new ClaimsIdentity(localClaims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            
            // Replace the principal in the context so the authentication middleware recognizes the user
            context.Principal = claimsPrincipal;
            
            // Sign in with cookies
            await context.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30)
                });
            
            // Set redirect URI directly to StudyChat since user is already signed in
            context.Properties.RedirectUri = "/StudyChat";
            
            logger.LogInformation("Google authentication successful for user: {Email}, UserId: {UserId}", email, user.Id);
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

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Account/Login");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

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
