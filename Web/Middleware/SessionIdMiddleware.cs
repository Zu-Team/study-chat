using System;
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
        // Check if session ID cookie exists
        if (!context.Request.Cookies.ContainsKey(SessionIdCookieName))
        {
            // Generate a new session ID (GUID)
            var sessionId = Guid.NewGuid().ToString("N"); // Format: 32 hex digits without hyphens
            
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
            _ = Task.Run(async () =>
            {
                try
                {
                    using var scope = context.RequestServices.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    
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
                catch (Exception ex)
                {
                    // Log error but don't break the request - cookie is still set
                    // Common error: column "session_id" does not exist - run migration SQL
                    var logger = scope.ServiceProvider.GetService<ILogger<SessionIdMiddleware>>();
                    logger?.LogWarning(ex, "Failed to save session to database. SessionId={SessionId}. Error: {Message}. " +
                        "Make sure you've run the migration SQL to add session_id column.", sessionId, ex.Message);
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

