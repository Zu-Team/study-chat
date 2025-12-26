using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Web.Data;
using Web.Models;

namespace Web.Middleware;

/// <summary>
/// Middleware that authenticates users based on session ID from cookie.
/// If the session has a UserId, the user is automatically authenticated.
/// This provides session-based authentication without requiring username/password on every request.
/// </summary>
public class SessionAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private const string SessionIdCookieName = "studychat_session_id";

    public SessionAuthenticationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip if user is already authenticated (e.g., via cookie authentication)
        // This middleware runs before UseAuthentication(), but cookie auth might have already run
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            await _next(context);
            return;
        }

        // Only query database if user is not authenticated
        {
            var sessionId = context.Request.Cookies[SessionIdCookieName];
            
            if (!string.IsNullOrEmpty(sessionId))
            {
                try
                {
                    using var scope = context.RequestServices.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    
                    // Find session with UserId (meaning user is logged in)
                    // Use AsNoTracking() for read-only query to improve performance
                    var session = await dbContext.Sessions
                        .AsNoTracking()
                        .Include(s => s.User)
                        .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.UserId != null);
                    
                    if (session != null && session.User != null)
                    {
                        // Create claims from the user
                        var claims = new List<Claim>
                        {
                            new Claim("studychat_user_id", session.User.Id.ToString()),
                            new Claim(ClaimTypes.NameIdentifier, session.User.Id.ToString()),
                            new Claim(ClaimTypes.Email, session.User.Email ?? string.Empty),
                            new Claim(ClaimTypes.Name, session.User.FullName ?? session.User.Email ?? string.Empty)
                        };

                        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal = new ClaimsPrincipal(identity);

                        // Sign in the user based on session
                        var authProperties = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            AllowRefresh = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30)
                        };

                        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProperties);
                    }
                }
                catch
                {
                    // Silently fail - don't break the request if authentication fails
                    // User will need to log in again
                }
            }
        }

        // Continue to the next middleware
        await _next(context);
    }
}

