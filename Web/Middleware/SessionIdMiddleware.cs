using System;

namespace Web.Middleware;

/// <summary>
/// Middleware that creates and manages a session ID cookie for first-time visitors.
/// The session ID is stored in a cookie and can be accessed via HttpContext.Items["SessionId"].
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
        }
        else
        {
            // Session ID already exists, retrieve it for use in controllers
            var existingSessionId = context.Request.Cookies[SessionIdCookieName];
            context.Items["SessionId"] = existingSessionId;
        }

        // Continue to the next middleware
        await _next(context);
    }
}

