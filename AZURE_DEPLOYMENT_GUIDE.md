# Deploy SmartStudy to Azure App Service

## Quick Start (3 Steps)

### Step 1: Publish Your Application
```powershell
cd Web
dotnet publish -c Release -o ../publish
Compress-Archive -Path ../publish/* -DestinationPath ../publish.zip -Force
```

### Step 2: Create Azure Resources
```powershell
# Set your unique app name (must be globally unique)
$appName = "smartstudy-yourname-$(Get-Random -Maximum 9999)"
$resourceGroup = "SmartStudy-RG"
$location = "eastus"

# Create resource group
az group create --name $resourceGroup --location $location

# Create App Service Plan (Free tier)
az appservice plan create --name "SmartStudy-Plan" --resource-group $resourceGroup --sku FREE --is-linux false

# Create Web App
az webapp create --name $appName --resource-group $resourceGroup --plan "SmartStudy-Plan" --runtime "DOTNET|9.0"
```

### Step 3: Deploy
```powershell
az webapp deployment source config-zip --resource-group $resourceGroup --name $appName --src ../publish.zip
```

Your app will be available at: `https://$appName.azurewebsites.net`

## Alternative: Use Azure Portal

1. Go to https://portal.azure.com
2. Click "Create a resource" → Search for "Web App"
3. Fill in:
   - **Name**: smartstudy-yourname (must be unique)
   - **Runtime stack**: .NET 9.0
   - **Operating System**: Windows
   - **App Service Plan**: Create new (Free tier)
4. Click "Review + create" → "Create"
5. Once created, go to your Web App → "Deployment Center"
6. Choose "Local Git" or "ZIP Deploy"
7. Upload your `publish.zip` file

## Benefits of Azure Hosting

- ✅ No local .NET SDK needed
- ✅ Automatic HTTPS/SSL
- ✅ Free tier available (Azure for Students)
- ✅ Auto-scaling
- ✅ Easy updates via Azure Portal or CLI
- ✅ Built-in monitoring and logging

## Updating Your App

After making changes:
```powershell
cd Web
dotnet publish -c Release -o ../publish
Compress-Archive -Path ../publish/* -DestinationPath ../publish.zip -Force
az webapp deployment source config-zip --resource-group SmartStudy-RG --name YOUR_APP_NAME --src ../publish.zip
```

