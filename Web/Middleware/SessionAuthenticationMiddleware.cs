using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Npgsql;
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
        // CRITICAL: This middleware now runs AFTER UseAuthentication()
        // Cookie authentication has already run, so context.User is populated if authenticated
        // Skip DB query entirely if user is already authenticated via cookie
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            await _next(context);
            return;
        }

        // Only query database if user is NOT authenticated and we have a session cookie
        var sessionId = context.Request.Cookies[SessionIdCookieName];
        
        if (string.IsNullOrEmpty(sessionId))
        {
            // No session cookie, nothing to do
            await _next(context);
            return;
        }

        // We have a session cookie but user is not authenticated
        // Query DB to check if session has a linked user (fallback authentication)
        try
        {
            using var scope = context.RequestServices.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var logger = scope.ServiceProvider.GetService<ILogger<SessionAuthenticationMiddleware>>();
            
            // OPTIMIZATION: Use projection with explicit join to fetch only needed fields
            // This avoids loading the entire User entity and reduces query complexity
            var sessionData = await dbContext.Sessions
                .AsNoTracking()
                .Where(s => s.SessionId == sessionId && s.UserId != null)
                .Join(
                    dbContext.Users,
                    session => session.UserId,
                    user => user.Id,
                    (session, user) => new
                    {
                        UserId = user.Id,
                        Email = user.Email,
                        FullName = user.FullName
                    })
                .FirstOrDefaultAsync();
            
            if (sessionData != null)
            {
                // Create claims from the user data
                var claims = new List<Claim>
                {
                    new Claim("studychat_user_id", sessionData.UserId.ToString()),
                    new Claim(ClaimTypes.NameIdentifier, sessionData.UserId.ToString()),
                    new Claim(ClaimTypes.Email, sessionData.Email ?? string.Empty),
                    new Claim(ClaimTypes.Name, sessionData.FullName ?? sessionData.Email ?? string.Empty)
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
                logger?.LogDebug("User {UserId} authenticated via session {SessionId}", sessionData.UserId, sessionId);
            }
        }
        catch (Npgsql.NpgsqlException dbEx)
        {
            // Database connection errors - log but don't break the request
            var logger = context.RequestServices.GetService<ILogger<SessionAuthenticationMiddleware>>();
            logger?.LogWarning(dbEx, "Database connection error during session authentication. SessionId={SessionId}, Error={Error}", 
                sessionId, dbEx.Message);
            // Continue - user will need to log in again if database is unavailable
        }
        catch (Microsoft.EntityFrameworkCore.DbUpdateException dbUpdateEx)
        {
            // Database update errors - log but don't break the request
            var logger = context.RequestServices.GetService<ILogger<SessionAuthenticationMiddleware>>();
            logger?.LogWarning(dbUpdateEx, "Database error during session authentication. SessionId={SessionId}, Error={Error}", 
                sessionId, dbUpdateEx.Message);
            // Continue - user will need to log in again
        }
        catch (Exception ex)
        {
            // Any other errors - log but don't break the request
            var logger = context.RequestServices.GetService<ILogger<SessionAuthenticationMiddleware>>();
            logger?.LogError(ex, "Unexpected error during session authentication. SessionId={SessionId}, Error={Error}", 
                sessionId, ex.Message);
            // Continue - user will need to log in again
        }

        // Continue to the next middleware
        await _next(context);
    }
}


