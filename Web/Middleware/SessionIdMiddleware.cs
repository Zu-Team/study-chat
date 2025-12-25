using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
                    
                    // Try to find a recent anonymous session (UserId is null) with matching IP/UserAgent
                    // Created within the last 10 minutes to account for OAuth redirect time
                    var recentSession = await dbContext.Sessions
                        .Where(s => s.UserId == null && 
                                    s.CreatedAt > DateTimeOffset.UtcNow.AddMinutes(-10) &&
                                    (string.IsNullOrEmpty(ipAddress) || s.IpAddress == ipAddress) &&
                                    (string.IsNullOrEmpty(userAgent) || s.UserAgent == userAgent))
                        .OrderByDescending(s => s.CreatedAt)
                        .FirstOrDefaultAsync();
                    
                    if (recentSession != null)
                    {
                        sessionId = recentSession.SessionId;
                        reusedExistingSession = true;
                        logger?.LogInformation("Reusing existing session {SessionId} for OAuth callback from IP {IpAddress}", sessionId, ipAddress);
                    }
                }
                catch (Exception ex)
                {
                    // If lookup fails, we'll create a new session below
                    var logger = context.RequestServices.GetService<ILogger<SessionIdMiddleware>>();
                    logger?.LogWarning(ex, "Failed to lookup existing session for OAuth callback, will create new one");
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

            // Save to database (fire and forget - don't block the request)
            // Only create new session if we didn't reuse an existing one
            if (!reusedExistingSession)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var scope = context.RequestServices.CreateScope();
                        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                        
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
                                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                                UserAgent = context.Request.Headers["User-Agent"].ToString(),
                                CreatedAt = DateTimeOffset.UtcNow,
                                LastAccessedAt = DateTimeOffset.UtcNow
                            };

                            dbContext.Sessions.Add(session);
                            await dbContext.SaveChangesAsync();
                        }
                        else
                        {
                            // Update existing session's last accessed time
                            existingSession.LastAccessedAt = DateTimeOffset.UtcNow;
                            existingSession.IpAddress = context.Connection.RemoteIpAddress?.ToString();
                            existingSession.UserAgent = context.Request.Headers["User-Agent"].ToString();
                            await dbContext.SaveChangesAsync();
                        }
                    }
                catch (Exception ex)
                {
                    // Log error but don't break the request - cookie is still set
                    // Common error: column "session_id" does not exist - run migration SQL
                    try
                    {
                        using var errorScope = context.RequestServices.CreateScope();
                        var logger = errorScope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                        logger?.LogWarning(ex, "Failed to save session to database. SessionId={SessionId}. Error: {Message}. " +
                            "Make sure you've run the migration SQL to add session_id column.", sessionId, ex.Message);
                    }
                    catch
                    {
                        // If logging fails, ignore - don't break the request
                    }
                }
            });
        }
        else
        {
            // Session ID already exists, retrieve it for use in controllers
            var existingSessionId = context.Request.Cookies[SessionIdCookieName];
            context.Items["SessionId"] = existingSessionId;

            // Update last accessed time in database (fire and forget)
            _ = Task.Run(async () =>
            {
                try
                {
                    using var scope = context.RequestServices.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    
                    var session = await dbContext.Sessions
                        .FirstOrDefaultAsync(s => s.SessionId == existingSessionId);
                    
                    if (session != null)
                    {
                        session.LastAccessedAt = DateTimeOffset.UtcNow;
                        await dbContext.SaveChangesAsync();
                    }
                }
                catch (Exception ex)
                {
                    // Log error but don't break the request
                    try
                    {
                        using var scope = context.RequestServices.CreateScope();
                        var logger = scope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                        logger?.LogWarning(ex, "Failed to update session last accessed time. SessionId={SessionId}", existingSessionId);
                    }
                    catch { }
                }
            });
        }

        // Continue to the next middleware
        await _next(context);
    }
}

