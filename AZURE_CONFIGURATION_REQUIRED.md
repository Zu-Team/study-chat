# Azure Configuration Required

## ⚠️ CRITICAL: Database Connection String

The application **requires** a database connection string to be configured in Azure App Settings.

### How to Configure in Azure Portal:

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your App Service: `studychat-bcd3a5hmgqcvgvam`
3. Go to **Configuration** → **Application settings**
4. Click **+ New application setting**
5. Add the following:

   **Name:** `ConnectionStrings__DefaultConnection`
   
   **Value:** `Host=db.uqqnqosybkmptahljxqu.supabase.co;Port=5432;Database=postgres;Username=postgres;Password=Zvo#0666 2025`

6. Click **Save** (this will restart the app)
7. Wait for the app to restart (usually 1-2 minutes)

### Why This Is Required:

- **Without this setting:** All database operations fail → Login, Registration, Chat, Sessions all break
- **With this setting:** The app can connect to Supabase database → Everything works

---

## Optional: Google OAuth (Only if you want "Continue with Google")

If you want Google login to work, add these settings:

**Name:** `Google__ClientId`  
**Value:** `[Your Google OAuth Client ID]`

**Name:** `Google__ClientSecret`  
**Value:** `[Your Google OAuth Client Secret]`

**Note:** Without these, only email/password login will work (which is fine for testing).

---

## Current Status

✅ **Code is fixed:** The app will start even if connection string is missing (but database operations will fail)  
❌ **Azure Configuration:** Connection string needs to be added in Azure Portal

---

## Quick Check

After adding the connection string, wait 1-2 minutes for the app to restart, then try logging in again.

If you still see errors, check:
1. Did you save the configuration? (Azure requires clicking "Save")
2. Did the app restart? (Check Azure Portal → App Service → Overview → Status)
3. Is the connection string correct? (Copy-paste the exact value above)

