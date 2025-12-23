# Configure Supabase settings in Azure Web App
# This script adds Supabase environment variables to the Azure Web App

$subscriptionId = "6c3a917e-b2b1-4b23-86fe-114f824f4630"
$resourceGroup = "Education.ai"
$webAppName = "studychat"

Write-Host "Configuring Supabase settings for Azure Web App: $webAppName" -ForegroundColor Green

# Get access token
Write-Host "Getting Azure access token..." -ForegroundColor Yellow
$token = (az account get-access-token --query accessToken -o tsv)

if (-not $token) {
    Write-Host "Error: Failed to get access token. Please run 'az login' first." -ForegroundColor Red
    exit 1
}

# Supabase configuration values
$supabaseSettings = @{
    "Supabase__Url" = "https://uqqnqosybkmptahljxqu.supabase.co"
    "Supabase__AnonKey" = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVxcW5xb3N5YmttcHRhaGxqeHF1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjIzODE4MDgsImV4cCI6MjA3Nzk1NzgwOH0.EyFrkaWIRbakqo2uxc7AgeGwpxoYRUNazZvObMjLsBk"
    "Supabase__ProjectRef" = "uqqnqosybkmptahljxqu"
    "Supabase__DbHost" = "db.uqqnqosybkmptahljxqu.supabase.co"
}

# Get current app settings
Write-Host "Fetching current application settings..." -ForegroundColor Yellow
$uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Web/sites/$webAppName/config/appsettings?api-version=2022-03-01"
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

try {
    $currentSettings = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
    $properties = $currentSettings.properties
    
    # Add or update Supabase settings
    Write-Host "Updating application settings..." -ForegroundColor Yellow
    foreach ($key in $supabaseSettings.Keys) {
        $properties.$key = $supabaseSettings[$key]
        Write-Host "  Setting $key = $($supabaseSettings[$key])" -ForegroundColor Cyan
    }
    
    # Update the settings
    $body = @{
        properties = $properties
    } | ConvertTo-Json -Depth 10
    
    $response = Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body $body
    
    Write-Host "`nSuccessfully configured Supabase settings!" -ForegroundColor Green
    Write-Host "The following settings have been added:" -ForegroundColor Yellow
    foreach ($key in $supabaseSettings.Keys) {
        Write-Host "  - $key" -ForegroundColor White
    }
    Write-Host "`nNote: You may need to restart the Web App for changes to take effect." -ForegroundColor Yellow
    
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Response: $($_.Exception.Response)" -ForegroundColor Red
    exit 1
}

