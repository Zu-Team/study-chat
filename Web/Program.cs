using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Web.Data;
using Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add DbContext with PostgreSQL provider
// Connection string is loaded from:
// 1. Environment variable: ConnectionStrings__DefaultConnection (highest priority - Azure App Settings)
// 2. User Secrets (Development only): ConnectionStrings:DefaultConnection
// 3. appsettings.json: ConnectionStrings:DefaultConnection (lowest priority, not recommended for secrets)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

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
// STARTUP CONFIGURATION VALIDATION
// ============================================
// Validate required configuration (without logging secrets)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var googleClientId = builder.Configuration["Google:ClientId"];
var googleClientSecret = builder.Configuration["Google:ClientSecret"];

var missingConfig = new List<string>();
if (string.IsNullOrWhiteSpace(connectionString))
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

if (missingConfig.Any())
{
    var errorMessage = $"CRITICAL: Missing required configuration values:\n" +
                       string.Join("\n", missingConfig.Select(c => $"  - {c}")) +
                       "\n\nPlease configure these in Azure App Settings or User Secrets.";
    Console.Error.WriteLine(errorMessage);
    throw new InvalidOperationException(errorMessage);
}

// Log validation success (without secrets) - will be logged when app starts
Console.WriteLine("[Startup] Configuration validation passed. All required settings are present.");
Console.WriteLine("[Startup] Database connection: CONFIGURED");
Console.WriteLine("[Startup] Google OAuth: CONFIGURED");

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
    // Note: Configuration is already validated above
    options.ClientId = googleClientId!;
    options.ClientSecret = googleClientSecret!;
    
    // Custom callback path (must match in Google Cloud Console)
    // For Azure: https://studychat.azurewebsites.net/Account/GoogleCallback
    options.CallbackPath = "/Account/GoogleCallback";
    options.SaveTokens = true;
    
    // Request additional scopes
    options.Scope.Add("email");
    options.Scope.Add("profile");
    
    // Map Google claims to standard claim types
    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
    options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
    options.ClaimActions.MapJsonKey("picture", "picture");
});

var app = builder.Build();

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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}")
    .WithStaticAssets();

app.Run();
