using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Web.Data;
using Web.Models;

namespace Web.Middleware;

/// <summary>
/// Middleware that creates and manages a session ID cookie for first-time visitors.
/// The session ID is stored in a cookie and saved to the database in the sessions table.
/// Before login: UserId is null. After login: UserId is set to the authenticated user's ID.
/// The session ID can be accessed via HttpContext.Items["SessionId"].
/// </summary>
public class SessionIdMiddleware
{
    private readonly RequestDelegate _next;
    private const string SessionIdCookieName = "studychat_session_id";
    private const int SessionIdExpirationDays = 365; // 1 year

    public SessionIdMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip session creation for OAuth callback paths to avoid creating duplicate sessions
        // OAuth callbacks might not have the cookie due to redirect flow, but we should preserve
        // the existing session rather than creating a new one
        var path = context.Request.Path.Value ?? "";
        var isOAuthCallback = path.Contains("/signin-google", StringComparison.OrdinalIgnoreCase) ||
                              path.Contains("/Account/GoogleCallback", StringComparison.OrdinalIgnoreCase) ||
                              path.Contains("/Account/GoogleRegisterCallback", StringComparison.OrdinalIgnoreCase);

        // Check if session ID cookie exists
        if (!context.Request.Cookies.ContainsKey(SessionIdCookieName))
        {
            // If this is an OAuth callback, try to find an existing session by IP/UserAgent first
            // before creating a new one. This prevents duplicate sessions during OAuth flow.
            string? sessionId = null;
            bool reusedExistingSession = false;
            
            if (isOAuthCallback)
            {
                try
                {
                    using var scope = context.RequestServices.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    var logger = scope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                    
                    var ipAddress = context.Connection.RemoteIpAddress?.ToString();
                    var userAgent = context.Request.Headers["User-Agent"].ToString();
                    
                    // Try to find a recent anonymous session (UserId is null) with matching UserAgent
                    // Created within the last 15 minutes to account for OAuth redirect time
                    // Use UserAgent as primary match (more reliable than IP which can change)
                    // Optimize: Query database directly instead of loading all sessions into memory
                    var matchedSession = await dbContext.Sessions
                        .AsNoTracking() // Read-only query
                        .Where(s => s.UserId == null && 
                                    s.CreatedAt > DateTimeOffset.UtcNow.AddMinutes(-15) &&
                                    (!string.IsNullOrEmpty(userAgent) && s.UserAgent == userAgent))
                        .OrderByDescending(s => s.CreatedAt)
                        .FirstOrDefaultAsync(); // Try UserAgent match first
                    
                    // Fallback: if no UserAgent match, get most recent session
                    if (matchedSession == null)
                    {
                        matchedSession = await dbContext.Sessions
                            .AsNoTracking()
                            .Where(s => s.UserId == null && 
                                        s.CreatedAt > DateTimeOffset.UtcNow.AddMinutes(-15))
                            .OrderByDescending(s => s.CreatedAt)
                            .FirstOrDefaultAsync();
                    }
                    
                    if (matchedSession != null)
                    {
                        sessionId = matchedSession.SessionId;
                        reusedExistingSession = true;
                        logger?.LogInformation("Reusing existing session {SessionId} for OAuth callback from IP {IpAddress}, UserAgent match: {UserAgentMatch}", 
                            sessionId, ipAddress, !string.IsNullOrEmpty(userAgent) && matchedSession.UserAgent == userAgent);
                    }
                    else
                    {
                        logger?.LogDebug("No recent anonymous session found for OAuth callback. Will create new one.");
                    }
                }
                catch (Exception ex)
                {
                    // If lookup fails, we'll create a new session below
                    var logger = context.RequestServices.GetService<ILogger<SessionIdMiddleware>>();
                    logger?.LogWarning(ex, "Failed to lookup existing session for OAuth callback, will create new one. Error: {Error}", ex.Message);
                }
            }
            
            // If no existing session found (or not OAuth callback), create a new one
            if (string.IsNullOrEmpty(sessionId))
            {
                sessionId = Guid.NewGuid().ToString("N"); // Format: 32 hex digits without hyphens
            }
            
            // Get environment to determine if we should use Secure cookies
            var environment = context.RequestServices.GetRequiredService<IHostEnvironment>();
            
            // Set cookie options
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true, // Prevents JavaScript access for security
                Secure = !environment.IsDevelopment(), // Only require HTTPS in production (allows HTTP in development)
                SameSite = SameSiteMode.Lax, // Allows OAuth redirects
                Expires = DateTimeOffset.UtcNow.AddDays(SessionIdExpirationDays),
                Path = "/" // Available site-wide
            };

            // Set the cookie
            context.Response.Cookies.Append(SessionIdCookieName, sessionId, cookieOptions);
            
            // Store in HttpContext.Items for easy access in controllers/views
            context.Items["SessionId"] = sessionId;

            // Save to database - await directly to ensure it completes
            // Only create new session if we didn't reuse an existing one
            if (!reusedExistingSession)
            {
                // Capture values from HttpContext
                var ipAddress = context.Connection.RemoteIpAddress?.ToString();
                var userAgent = context.Request.Headers["User-Agent"].ToString();
                
                try
                {
                    using var scope = context.RequestServices.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    var logger = scope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                    
                    // Double-check if session already exists (race condition protection)
                    var existingSession = await dbContext.Sessions
                        .FirstOrDefaultAsync(s => s.SessionId == sessionId);
                    
                    if (existingSession == null)
                    {
                        var session = new Session
                        {
                            SessionId = sessionId,
                            UserId = null, // Null before login
                            Title = null, // Anonymous session, no title needed
                            IpAddress = ipAddress,
                            UserAgent = userAgent,
                            CreatedAt = DateTimeOffset.UtcNow,
                            LastAccessedAt = DateTimeOffset.UtcNow
                        };

                        dbContext.Sessions.Add(session);
                        await dbContext.SaveChangesAsync();
                        logger?.LogInformation("New session created in database: {SessionId}", sessionId);
                    }
                    else
                    {
                        // Update existing session's last accessed time
                        existingSession.LastAccessedAt = DateTimeOffset.UtcNow;
                        existingSession.IpAddress = ipAddress;
                        existingSession.UserAgent = userAgent;
                        await dbContext.SaveChangesAsync();
                        logger?.LogDebug("Session {SessionId} LastAccessedAt updated in DB.", sessionId);
                    }
                }
                catch (Npgsql.NpgsqlException dbEx)
                {
                    // Database connection errors - log but don't break the request
                    var logger = context.RequestServices.GetService<ILogger<SessionIdMiddleware>>();
                    logger?.LogError(dbEx, "❌ DATABASE CONNECTION ERROR while saving session. SessionId={SessionId}, SQLState={SqlState}, Error={Error}. " +
                        "This indicates the connection string is NOT configured correctly in Azure App Settings. " +
                        "Please set ConnectionStrings__DefaultConnection or Supabase__DbPassword in Azure Portal.", 
                        sessionId, dbEx.SqlState, dbEx.Message);
                    // Continue - session ID is still set in cookie, just not saved to DB
                }
                catch (Microsoft.EntityFrameworkCore.DbUpdateException dbUpdateEx)
                {
                    // Database update errors - log but don't break the request
                    var logger = context.RequestServices.GetService<ILogger<SessionIdMiddleware>>();
                    var innerEx = dbUpdateEx.InnerException;
                    logger?.LogError(dbUpdateEx, "❌ DATABASE UPDATE ERROR while saving session. SessionId={SessionId}, Error={Error}, InnerError={InnerError}. " +
                        "This may indicate a schema mismatch or connection issue.", 
                        sessionId, dbUpdateEx.Message, innerEx?.Message ?? "None");
                    // Continue - session ID is still set in cookie
                }
                catch (Exception ex)
                {
                    // Any other errors - log but don't break the request
                    var logger = context.RequestServices.GetService<ILogger<SessionIdMiddleware>>();
                    logger?.LogError(ex, "❌ UNEXPECTED ERROR while saving session to database. SessionId={SessionId}, Error={Error}, Type={ExceptionType}. " +
                        "Make sure you've run the migration SQL to add session_id column and the connection string is configured.", 
                        sessionId, ex.Message, ex.GetType().Name);
                    // Continue - session ID is still set in cookie
                }
            }
        }
        else
        {
            // Session ID already exists, retrieve it for use in controllers
            var existingSessionId = context.Request.Cookies[SessionIdCookieName];
            context.Items["SessionId"] = existingSessionId;

            // Update last accessed time in database - do this in background to avoid blocking requests
            // Only update if it's been more than 5 minutes since last update to reduce DB load
            _ = Task.Run(async () =>
            {
                try
                {
                    using var scope = context.RequestServices.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    var logger = scope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                    
                    // Use AsNoTracking for read-only check, then attach for update if needed
                    var session = await dbContext.Sessions
                        .AsNoTracking()
                        .FirstOrDefaultAsync(s => s.SessionId == existingSessionId);
                    
                    if (session != null)
                    {
                        // Only update if it's been more than 5 minutes (reduce database writes)
                        var timeSinceLastUpdate = DateTimeOffset.UtcNow - session.LastAccessedAt;
                        if (timeSinceLastUpdate.TotalMinutes >= 5)
                        {
                            // Attach and update only the LastAccessedAt field
                            var sessionToUpdate = new Session { Id = session.Id, SessionId = session.SessionId };
                            dbContext.Sessions.Attach(sessionToUpdate);
                            sessionToUpdate.LastAccessedAt = DateTimeOffset.UtcNow;
                            await dbContext.SaveChangesAsync();
                            logger?.LogDebug("Session {SessionId} LastAccessedAt updated in DB.", existingSessionId);
                        }
                    }
                    else
                    {
                        logger?.LogWarning("Session {SessionId} not found in database when updating LastAccessedAt.", existingSessionId);
                    }
                }
                catch (Npgsql.NpgsqlException dbEx)
                {
                    // Database connection errors - log but don't break the request
                    try
                    {
                        using var errorScope = context.RequestServices.CreateScope();
                        var logger = errorScope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                        logger?.LogWarning(dbEx, "Database connection error while updating session. SessionId={SessionId}, Error={Error}", 
                            existingSessionId, dbEx.Message);
                    }
                    catch { }
                }
                catch (Microsoft.EntityFrameworkCore.DbUpdateException dbUpdateEx)
                {
                    // Database update errors - log but don't break the request
                    try
                    {
                        using var errorScope = context.RequestServices.CreateScope();
                        var logger = errorScope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                        logger?.LogWarning(dbUpdateEx, "Database update error while updating session. SessionId={SessionId}, Error={Error}", 
                            existingSessionId, dbUpdateEx.Message);
                    }
                    catch { }
                }
                catch (Exception ex)
                {
                    // Any other errors - log but don't break the request
                    try
                    {
                        using var errorScope = context.RequestServices.CreateScope();
                        var logger = errorScope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                        logger?.LogError(ex, "Unexpected error while updating session last accessed time. SessionId={SessionId}, Error={Error}", 
                            existingSessionId, ex.Message);
                    }
                    catch { }
                }
            });
        }

        // Continue to the next middleware
        await _next(context);
    }
}

