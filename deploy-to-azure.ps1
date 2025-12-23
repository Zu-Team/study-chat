# Azure App Service Deployment Script for SmartStudy
# This script creates an Azure App Service and deploys your ASP.NET Core app

# Configuration variables - customize these
$resourceGroupName = "SmartStudy-RG"
$appServiceName = "smartstudy-$(Get-Random -Maximum 9999)"  # Must be globally unique
$location = "eastus"  # Change to your preferred region
$appServicePlanName = "SmartStudy-Plan"

Write-Host "Creating Azure resources for SmartStudy..." -ForegroundColor Green

# Create resource group
Write-Host "Creating resource group: $resourceGroupName" -ForegroundColor Yellow
az group create --name $resourceGroupName --location $location

# Create App Service Plan (Free tier)
Write-Host "Creating App Service Plan: $appServicePlanName" -ForegroundColor Yellow
az appservice plan create `
    --name $appServicePlanName `
    --resource-group $resourceGroupName `
    --sku FREE `
    --is-linux false

# Create Web App with .NET 9.0 runtime
Write-Host "Creating Web App: $appServiceName" -ForegroundColor Yellow
az webapp create `
    --name $appServiceName `
    --resource-group $resourceGroupName `
    --plan $appServicePlanName `
    --runtime "DOTNET|9.0"

# Configure app settings
Write-Host "Configuring app settings..." -ForegroundColor Yellow
az webapp config appsettings set `
    --resource-group $resourceGroupName `
    --name $appServiceName `
    --settings ASPNETCORE_ENVIRONMENT="Production"

# Deploy the application
Write-Host "Deploying application..." -ForegroundColor Yellow
cd Web
az webapp deployment source config-zip `
    --resource-group $resourceGroupName `
    --name $appServiceName `
    --src "../publish.zip"

Write-Host "`nDeployment complete!" -ForegroundColor Green
Write-Host "Your app is available at: https://$appServiceName.azurewebsites.net" -ForegroundColor Cyan
Write-Host "`nTo update your app in the future, run:" -ForegroundColor Yellow
Write-Host "  cd Web" -ForegroundColor White
Write-Host "  dotnet publish -c Release -o ../publish" -ForegroundColor White
Write-Host "  Compress-Archive -Path ../publish/* -DestinationPath ../publish.zip -Force" -ForegroundColor White
Write-Host "  az webapp deployment source config-zip --resource-group $resourceGroupName --name $appServiceName --src ../publish.zip" -ForegroundColor White

