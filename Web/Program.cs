using Microsoft.EntityFrameworkCore;
using Web.Data;
using Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add DbContext with PostgreSQL provider
// Connection string is loaded from:
// 1. Environment variable: ConnectionStrings__DefaultConnection (highest priority)
// 2. User Secrets (Development only): ConnectionStrings:DefaultConnection
// 3. appsettings.json: ConnectionStrings:DefaultConnection (lowest priority, not recommended for secrets)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// MIGRATION INSTRUCTIONS (run these commands in the Web directory):
// 1. Create initial migration:
//    dotnet ef migrations add InitialCreate
//
// 2. Apply migrations to database:
//    dotnet ef database update
//
// See DATABASE_SETUP.md for detailed instructions and connection string configuration.

// Register services
builder.Services.AddScoped<IStudentService, StudentService>();

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

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}")
    .WithStaticAssets();


app.Run();
