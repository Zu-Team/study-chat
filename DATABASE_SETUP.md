# Database Setup Instructions

## Prerequisites

1. Ensure you have the .NET EF Core tools installed:
   ```bash
   dotnet tool install --global dotnet-ef
   ```

## Connection String Configuration

### Option 1: Environment Variable (Recommended for Production)
Set the connection string as an environment variable:
```bash
# Windows PowerShell
$env:ConnectionStrings__DefaultConnection = "Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD"

# Windows CMD
set ConnectionStrings__DefaultConnection=Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD

# Linux/Mac
export ConnectionStrings__DefaultConnection="Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD"
```

### Option 2: User Secrets (Recommended for Development)
```bash
dotnet user-secrets init
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD"
```

### Option 3: appsettings.json (NOT Recommended - Only for local testing)
**⚠️ WARNING: Never commit appsettings.json with real passwords to source control!**

Replace `REPLACE_ME` in `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD"
  }
}
```

## Database Migrations

### Create Initial Migration
```bash
cd Web
dotnet ef migrations add InitialCreate
```

### Apply Migrations to Database
```bash
dotnet ef database update
```

### Additional Migration Commands
```bash
# Create a new migration after model changes
dotnet ef migrations add MigrationName

# Update database with latest migrations
dotnet ef database update

# Remove last migration (if not applied)
dotnet ef migrations remove

# List all migrations
dotnet ef migrations list
```

## Connection String Format

For PostgreSQL (Supabase):
```
Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=YOUR_PASSWORD
```

**Important Security Notes:**
- Never commit connection strings with real passwords to Git
- Use environment variables or user secrets in development
- Use Azure App Service Configuration (Environment Variables) in production
- The `appsettings.Development.json` file should NOT contain real connection strings

## Testing the Setup

1. Run the application:
   ```bash
   dotnet run
   ```

2. Navigate to: `https://localhost:5001/Student` (or the port shown in console)

3. You should see the Students page. If the database is empty, you'll see a message indicating no students found.

## Troubleshooting

### Error: "No connection string named 'DefaultConnection' could be found"
- Ensure you've set the connection string using one of the methods above
- Check that the environment variable name uses double underscores: `ConnectionStrings__DefaultConnection`

### Error: "Unable to connect to database"
- Verify your Supabase database is running
- Check that the host, port, username, and password are correct
- Ensure your IP is allowed in Supabase firewall settings (if applicable)

### Error: "Table 'Students' does not exist"
- Run the migrations: `dotnet ef database update`
- Verify the migration was applied successfully

