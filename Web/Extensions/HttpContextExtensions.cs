namespace Web.Extensions;

/// <summary>
/// Extension methods for HttpContext to access session ID
/// </summary>
public static class HttpContextExtensions
{
    private const string SessionIdKey = "SessionId";
    private const string SessionIdCookieName = "studychat_session_id";

    /// <summary>
    /// Gets the session ID from HttpContext.Items (set by SessionIdMiddleware)
    /// </summary>
    /// <param name="context">The HTTP context</param>
    /// <returns>The session ID string, or null if not set</returns>
    public static string? GetSessionId(this HttpContext context)
    {
        if (context.Items.TryGetValue(SessionIdKey, out var sessionId))
        {
            return sessionId?.ToString();
        }

        // Fallback: try to get from cookie directly
        return context.Request.Cookies[SessionIdCookieName];
    }

    /// <summary>
    /// Checks if a session ID exists for this request
    /// </summary>
    /// <param name="context">The HTTP context</param>
    /// <returns>True if session ID exists, false otherwise</returns>
    public static bool HasSessionId(this HttpContext context)
    {
        return !string.IsNullOrEmpty(context.GetSessionId());
    }
}

