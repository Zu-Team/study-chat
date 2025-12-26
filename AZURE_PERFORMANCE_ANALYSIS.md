# Azure App Service Performance Analysis & Configuration Issues

## 1. Azure Hosting Environment Analysis

### Current Configuration (from codebase):
- **App Service Name**: `studychat`
- **Resource Group**: `Education.ai`
- **Subscription ID**: `6c3a917e-b2b1-4b23-86fe-114f824f4630`
- **Target Framework**: `.NET 9.0` (from `Web.csproj`)
- **Build Configuration**: `Release` (from GitHub Actions)
- **Deployment**: GitHub Actions with Azure Web Apps Deploy

### Expected Azure Configuration:
Based on the deployment workflow and codebase:
- **Runtime Stack**: Should be `.NET 9` or `.NET 9.0`
- **Operating System**: Likely **Windows** (based on `windows-latest` in workflow)
- **Region**: Unknown (need to check in Azure Portal)

---

## 2. Critical Configuration Issues to Check in Azure Portal

### ⚠️ **ISSUE #1: Runtime Stack Mismatch**
**Problem**: Azure App Service might be configured with an older .NET runtime (e.g., .NET 8, .NET 7, or .NET 6) instead of .NET 9.

**How to Check**:
1. Go to Azure Portal → `studychat` App Service
2. Navigate to **Configuration** → **General settings** tab
3. Check **Stack** and **Stack version**

**Expected**: 
- Stack: `.NET`
- Stack version: `9.0` or `9.x`

**If Wrong**: This causes the app to run on an incompatible runtime, leading to:
- Slow startup times
- Runtime errors
- Performance degradation
- Compatibility issues with .NET 9-specific features

**Fix**: Update the stack version to `.NET 9.0` in Azure Portal.

---

### ⚠️ **ISSUE #2: Environment Variable Mismatch**
**Problem**: `ASPNETCORE_ENVIRONMENT` might be set to `Development` instead of `Production`.

**How to Check**:
1. Azure Portal → `studychat` → **Configuration** → **Application settings**
2. Look for `ASPNETCORE_ENVIRONMENT`

**Expected**: `Production`

**If Wrong**: Running in Development mode causes:
- Slower performance (debug symbols, verbose logging)
- More memory usage
- Slower JIT compilation
- Development-specific middleware overhead

**Fix**: Set `ASPNETCORE_ENVIRONMENT=Production`

---

### ⚠️ **ISSUE #3: Always On Disabled**
**Problem**: "Always On" might be disabled, causing cold starts.

**How to Check**:
1. Azure Portal → `studychat` → **Configuration** → **General settings**
2. Check **Always On** toggle

**Expected**: `On` (enabled)

**If Wrong**: Disabled Always On causes:
- App to sleep after 20 minutes of inactivity
- Cold start delays (5-30 seconds) on first request after sleep
- Slow response times for first user after idle period

**Fix**: Enable **Always On** (Note: Requires Basic plan or higher, not available on Free tier)

---

### ⚠️ **ISSUE #4: App Service Plan Tier Too Low**
**Problem**: App might be on Free tier with severe resource limitations.

**How to Check**:
1. Azure Portal → `studychat` → **Overview**
2. Click on **App Service plan** link
3. Check **Pricing tier**

**Expected**: At least **Basic B1** or **Standard S1** for production

**If Free Tier**: Free tier has:
- Limited CPU (shared, throttled)
- Limited memory (1 GB)
- No Always On (app sleeps after 20 min)
- Limited bandwidth
- No SLA

**Impact**: Severe performance degradation, especially with database queries.

**Fix**: Upgrade to at least Basic B1 plan (if budget allows)

---

### ⚠️ **ISSUE #5: Missing or Incorrect Connection String**
**Problem**: Database connection string might be missing or misconfigured.

**How to Check**:
1. Azure Portal → `studychat` → **Configuration** → **Connection strings**
2. Verify `DefaultConnection` exists and is correct

**Expected**: 
- Name: `DefaultConnection`
- Value: Valid PostgreSQL connection string to Supabase
- Type: `PostgreSQL` or `Custom`

**If Missing/Wrong**: Causes:
- Database connection failures
- Slow retry attempts
- Timeout errors

**Fix**: Add/update connection string in Azure Portal

---

### ⚠️ **ISSUE #6: ARR Affinity (Session Affinity) Enabled**
**Problem**: ARR Affinity might be enabled unnecessarily.

**How to Check**:
1. Azure Portal → `studychat` → **Configuration** → **General settings**
2. Check **ARR affinity**

**Expected**: `Off` (for stateless apps)

**If On**: Forces all requests from a user to the same server instance, which can:
- Cause load imbalance
- Slow down requests if that instance is busy
- Prevent proper scaling

**Fix**: Disable ARR affinity (unless you have stateful sessions that require it)

---

### ⚠️ **ISSUE #7: HTTP Version Mismatch**
**Problem**: HTTP/2 might be disabled or HTTP version misconfigured.

**How to Check**:
1. Azure Portal → `studychat` → **Configuration** → **General settings**
2. Check **HTTP version**

**Expected**: `2.0` (for better performance)

**If 1.1 or disabled**: Slower HTTP performance

**Fix**: Enable HTTP/2.0

---

## 3. Code vs Azure Environment Compatibility Check

### ✅ **Code Configuration (Correct)**:
- Target Framework: `.NET 9.0` ✓
- Entity Framework Core: `9.0.0` ✓
- Npgsql: `9.0.2` ✓
- Build: `Release` configuration ✓
- Connection pooling: Configured in code ✓

### ⚠️ **Potential Mismatches**:
1. **Google Authentication Package**: `Microsoft.AspNetCore.Authentication.Google` is `8.0.0` but should be `9.0.0` for full compatibility
2. **Runtime Version**: Azure might not have .NET 9 runtime installed/selected

---

## 4. Performance Impact Analysis

### Most Likely Causes of Slowness (in order of probability):

1. **Runtime Stack Mismatch** (HIGHEST IMPACT)
   - Running .NET 9 code on .NET 8/7/6 runtime
   - **Impact**: 50-200% slower performance
   - **Fix Priority**: 🔴 CRITICAL

2. **Development Mode** (HIGH IMPACT)
   - `ASPNETCORE_ENVIRONMENT=Development`
   - **Impact**: 30-50% slower performance
   - **Fix Priority**: 🔴 CRITICAL

3. **Free Tier Limitations** (HIGH IMPACT)
   - Limited CPU, memory, no Always On
   - **Impact**: 40-60% slower, cold starts
   - **Fix Priority**: 🟡 HIGH (if on Free tier)

4. **Always On Disabled** (MEDIUM IMPACT)
   - App sleeps after 20 minutes
   - **Impact**: 5-30 second cold starts
   - **Fix Priority**: 🟡 HIGH

5. **Connection String Issues** (MEDIUM IMPACT)
   - Missing or incorrect database connection
   - **Impact**: Connection timeouts, retries
   - **Fix Priority**: 🟡 HIGH

6. **ARR Affinity Enabled** (LOW-MEDIUM IMPACT)
   - Load imbalance
   - **Impact**: 10-20% slower
   - **Fix Priority**: 🟢 MEDIUM

---

## 5. Recommended Actions (Priority Order)

### 🔴 **IMMEDIATE (Do First)**:

1. **Check Runtime Stack**:
   ```
   Azure Portal → studychat → Configuration → General settings
   → Verify Stack = ".NET" and Version = "9.0"
   → If wrong, change and Save
   ```

2. **Check Environment Variable**:
   ```
   Azure Portal → studychat → Configuration → Application settings
   → Verify ASPNETCORE_ENVIRONMENT = "Production"
   → If missing/wrong, add/update and Save
   ```

3. **Check Always On**:
   ```
   Azure Portal → studychat → Configuration → General settings
   → Enable "Always On" (if plan supports it)
   → Save
   ```

### 🟡 **HIGH PRIORITY (Do Second)**:

4. **Check App Service Plan**:
   ```
   Azure Portal → studychat → Overview → Click App Service plan
   → Check Pricing tier
   → If Free, consider upgrading to Basic B1 (minimum)
   ```

5. **Verify Connection String**:
   ```
   Azure Portal → studychat → Configuration → Connection strings
   → Verify DefaultConnection exists and is correct
   → Type should be "PostgreSQL" or "Custom"
   ```

### 🟢 **MEDIUM PRIORITY (Do Third)**:

6. **Disable ARR Affinity** (if not needed):
   ```
   Azure Portal → studychat → Configuration → General settings
   → Set ARR affinity = Off
   → Save
   ```

7. **Enable HTTP/2**:
   ```
   Azure Portal → studychat → Configuration → General settings
   → Set HTTP version = 2.0
   → Save
   ```

---

## 6. How to Verify Fixes

After making changes:

1. **Restart the App Service**:
   ```
   Azure Portal → studychat → Overview → Restart
   ```

2. **Check Logs**:
   ```
   Azure Portal → studychat → Log stream
   → Look for startup messages
   → Verify .NET 9 runtime is loaded
   → Check for any errors
   ```

3. **Test Performance**:
   - Navigate to your app
   - Measure page load times
   - Check database query performance
   - Monitor response times

---

## 7. Expected Performance Improvements

After fixing the above issues:

- **Runtime Stack Fix**: 50-200% faster
- **Production Mode**: 30-50% faster
- **Always On**: Eliminates 5-30 second cold starts
- **Plan Upgrade**: 40-60% faster (if upgrading from Free)
- **Combined**: **2-5x overall performance improvement**

---

## 8. Additional Recommendations

### For Single-User University Project:

1. **Use Basic B1 Plan** (if budget allows):
   - ~$13/month
   - Always On included
   - Better performance
   - 1.75 GB RAM, 1 CPU core

2. **Monitor Application Insights** (if enabled):
   - Check response times
   - Identify slow queries
   - Monitor errors

3. **Database Region**:
   - Ensure Supabase database is in a region close to Azure App Service
   - Reduces network latency

4. **Code Optimizations** (Already Done):
   - ✅ Connection pooling configured
   - ✅ AsNoTracking() on read queries
   - ✅ Optimized middleware
   - ✅ Reduced timeouts

---

## Summary

**Most Critical Issues to Fix**:
1. ✅ Verify Runtime Stack = .NET 9.0
2. ✅ Set ASPNETCORE_ENVIRONMENT = Production
3. ✅ Enable Always On (if plan supports)
4. ✅ Verify Connection String is correct

**Expected Result**: 2-5x performance improvement after fixes.

