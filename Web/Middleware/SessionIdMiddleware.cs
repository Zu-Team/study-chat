using System;
using Microsoft.EntityFrameworkCore;
using Web.Data;
using Web.Models;

namespace Web.Middleware;

/// <summary>
/// Middleware that creates and manages a session ID cookie for first-time visitors.
/// The session ID is stored in a cookie and saved to the database in the visitor_sessions table.
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
            
            // Set cookie options
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true, // Prevents JavaScript access for security
                Secure = true, // Only sent over HTTPS
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
                    
                    var visitorSession = new VisitorSession
                    {
                        SessionId = sessionId,
                        IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                        UserAgent = context.Request.Headers["User-Agent"].ToString(),
                        CreatedAt = DateTimeOffset.UtcNow,
                        LastAccessedAt = DateTimeOffset.UtcNow
                    };

                    dbContext.VisitorSessions.Add(visitorSession);
                    await dbContext.SaveChangesAsync();
                }
                catch
                {
                    // Silently fail - don't break the request if DB save fails
                    // This ensures the cookie is still set even if DB is unavailable
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
                    
                    var visitorSession = await dbContext.VisitorSessions
                        .FirstOrDefaultAsync(vs => vs.SessionId == existingSessionId);
                    
                    if (visitorSession != null)
                    {
                        visitorSession.LastAccessedAt = DateTimeOffset.UtcNow;
                        await dbContext.SaveChangesAsync();
                    }
                }
                catch
                {
                    // Silently fail - don't break the request if DB update fails
                }
            });
        }

        // Continue to the next middleware
        await _next(context);
    }
}

