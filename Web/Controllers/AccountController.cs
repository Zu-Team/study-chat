using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Web.Services;
using Web.Data;
using Web.Models;
using Web.Extensions;

namespace Web.Controllers;

public class AccountController : Controller
{
    private readonly UserService _userService;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<AccountController> _logger;
    private readonly IConfiguration _configuration;
    private const string SessionIdCookieName = "studychat_session_id";

    public AccountController(UserService userService, ApplicationDbContext dbContext, ILogger<AccountController> logger, IConfiguration configuration)
    {
        _userService = userService;
        _dbContext = dbContext;
        _logger = logger;
        _configuration = configuration;
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string email, string password, string? returnUrl = null)
    {
        var traceId = HttpContext.TraceIdentifier;

        if (string.IsNullOrWhiteSpace(email))
        {
            ModelState.AddModelError(nameof(email), "Email is required.");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            ModelState.AddModelError(nameof(password), "Password is required.");
        }

        if (!ModelState.IsValid)
        {
            return View();
        }

        // Prefer explicit param, otherwise honor common ReturnUrl query param.
        returnUrl ??= Request.Query["ReturnUrl"].ToString();
        if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
        {
            returnUrl = Url.Action("Index", "StudyChat") ?? "/StudyChat/Index";
        }

        try
        {
            var normalizedEmail = email.Trim();
            var user = await _userService.GetUserByEmailAsync(normalizedEmail);

            // Avoid user enumeration: use same message for "not found" and "wrong password".
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return View();
            }

            if (string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                ModelState.AddModelError(string.Empty, "This account does not have a local password. Please use Google sign-in.");
                return View();
            }

            var hasher = new PasswordHasher<Web.Models.User>();
            var result = hasher.VerifyHashedPassword(user, user.PasswordHash, password);
            if (result == PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return View();
            }

            // Optional rehash (don't let DB UPDATE permission issues break sign-in).
            string? newPasswordHash = null;
            if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                newPasswordHash = hasher.HashPassword(user, password);
            }

            var claims = new List<Claim>
            {
                new Claim("studychat_user_id", user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.FullName ?? user.Email ?? string.Empty)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            var props = new AuthenticationProperties
            {
                IsPersistent = false, // Session cookie - deleted when browser closes
                AllowRefresh = true
            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props);

            // Link session to user (update session with UserId) - MUST be synchronous
            // StudyChat/Index checks session.UserId, so it must be set before redirect
            await LinkSessionToUserAsync(user.Id);

            // Best-effort: persist last_login_at and optional password rehash - do in background
            // If UPDATE is blocked by DB policies/RLS, keep the user logged in.
            _ = Task.Run(async () =>
            {
                try
                {
                    await _userService.TryUpdateLoginMetadataAsync(user, newPasswordHash);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Background login metadata update failed for user {UserId}", user.Id);
                }
            });
            
            return LocalRedirect(returnUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Local login failed unexpectedly. TraceId={TraceId}, Email={Email}", traceId, email);
            ModelState.AddModelError(string.Empty, $"Unexpected server error while logging in. Ref: {traceId}");
            return View();
        }
    }

    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(string fullName, string email, string password)
    {
        var traceId = HttpContext.TraceIdentifier;

        if (string.IsNullOrWhiteSpace(fullName))
        {
            ModelState.AddModelError(nameof(fullName), "Full name is required.");
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            ModelState.AddModelError(nameof(email), "Email is required.");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            ModelState.AddModelError(nameof(password), "Password is required.");
        }
        else if (password.Length < 8)
        {
            ModelState.AddModelError(nameof(password), "Password must be at least 8 characters.");
        }

        if (!ModelState.IsValid)
        {
            return View();
        }

        try
        {
            // Create the DB row (this is your DB connectivity check).
            await _userService.CreateLocalUserAsync(email, password, fullName);
            return RedirectToAction("Login", new { message = "Account created successfully. You can now log in." });
        }
        catch (InvalidOperationException ex)
        {
            // e.g., duplicate email
            ModelState.AddModelError(string.Empty, ex.Message);
            return View();
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Database error while creating local account. TraceId={TraceId}, Email={Email}, InnerException={InnerException}", 
                traceId, email, ex.InnerException?.Message);
            
            // Check if it's a transient failure (connection issue)
            if (ex.InnerException?.Message?.Contains("transient", StringComparison.OrdinalIgnoreCase) == true ||
                ex.InnerException?.Message?.Contains("timeout", StringComparison.OrdinalIgnoreCase) == true)
            {
                ModelState.AddModelError(string.Empty, 
                    "Unable to connect to the database. Please try again in a few moments. If the problem persists, contact support.");
            }
            else
            {
                ModelState.AddModelError(string.Empty, $"Database error while creating the account. Ref: {traceId}");
            }
            return View();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while creating local account. TraceId={TraceId}, Email={Email}, ExceptionType={ExceptionType}", 
                traceId, email, ex.GetType().Name);
            
            // Check if it's a connection/network issue
            if (ex.Message.Contains("transient", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("connection", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError(string.Empty, 
                    "Unable to connect to the database. Please try again in a few moments. If the problem persists, contact support.");
            }
            else
            {
                ModelState.AddModelError(string.Empty, $"Unexpected server error while creating the account. Ref: {traceId}");
            }
            return View();
        }
    }

    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    public IActionResult ForgotPassword(string email)
    {
        // TODO: Implement forgot password logic
        // For now, this is just a placeholder
        ViewBag.Message = "If an account exists with this email, a password reset link has been sent.";
        return View();
    }

    public IActionResult GoogleLogin()
    {
        // Always return to GoogleCallback after the remote login completes.
        // This gives us a single place to verify the cookie user exists and then redirect to the final page.
        var returnUrl = Request.Query["returnUrl"].ToString();
        if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
        {
            returnUrl = Url.Action("Index", "StudyChat") ?? "/StudyChat/Index";
        }

        var redirectUri = Url.Action("GoogleCallback", "Account", new { returnUrl }) ?? "/Account/GoogleCallback";
        var properties = new AuthenticationProperties { RedirectUri = redirectUri };
        properties.Items["flow"] = "login";
        return Challenge(properties, "Google");
    }

    [AllowAnonymous]
    public async Task<IActionResult> GoogleRegister()
    {
        // Ensure we start from a clean session (avoid reusing an existing auth cookie).
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        var redirectUri = Url.Action("GoogleRegisterCallback", "Account") ?? "/Account/GoogleRegisterCallback";
        var properties = new AuthenticationProperties { RedirectUri = redirectUri };
        properties.Items["flow"] = "register";
        return Challenge(properties, "Google");
    }

    [AllowAnonymous]
    public async Task<IActionResult> GoogleRegisterCallback()
    {
        var traceId = HttpContext.TraceIdentifier;

        try
        {
            // In the "register" flow we intentionally do NOT sign the user into the app.
            // We only create the account if it doesn't exist, then redirect to Login.

            // The Google handler signs into the cookie scheme (SignInScheme) before we get here,
            // so we can read claims from HttpContext.User (or explicitly authenticate the cookie).
            var principal = User;
            if (principal?.Identity?.IsAuthenticated != true)
            {
                var cookieResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                principal = cookieResult.Principal ?? principal;
            }

            var claims = principal?.Claims;
            var googleSub = claims?.FirstOrDefault(c => c.Type == "sub" || c.Type == ClaimTypes.NameIdentifier)?.Value;
            var email = claims?.FirstOrDefault(c => c.Type == "email" || c.Type == ClaimTypes.Email)?.Value;
            var name = claims?.FirstOrDefault(c => c.Type == "name" || c.Type == ClaimTypes.Name)?.Value;

            if (string.IsNullOrWhiteSpace(googleSub) || string.IsNullOrWhiteSpace(email))
            {
                return RedirectToAction("Login", "Account",
                    new { error = $"Google sign-up did not return required profile info. Ref: {traceId}" });
            }

            var created = await _userService.CreateGoogleUserIfNotExistsAsync(googleSub, email, name);

            // End the temporary cookie session created by the Google handler.
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction("Login", "Account", new
            {
                message = created
                    ? "Google account created successfully. Please sign in."
                    : "An account with this email already exists. Please sign in."
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GoogleRegisterCallback failed. TraceId={TraceId}", traceId);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Account",
                new { error = $"Google sign-up failed due to a server error. Ref: {traceId}" });
        }
    }

    [AllowAnonymous]
    public async Task<IActionResult> GoogleCallback()
    {
        var traceId = HttpContext.TraceIdentifier;
        var debugAuthEnabled = string.Equals(_configuration["Debug:Auth"], "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            // In this app, the Google handler signs in the cookie during OnTicketReceived.
            // So this endpoint should usually just observe the cookie-authenticated user and redirect.
            var returnUrl = Request.Query["returnUrl"].ToString();
            if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
            {
                returnUrl = Url.Action("Index", "StudyChat") ?? "/StudyChat/Index";
            }

            if (User.Identity?.IsAuthenticated == true)
            {
                // Link session to user if not already linked (fallback in case OnTicketReceived didn't do it)
                // Do this in background to avoid blocking the redirect (non-critical operation)
                var userIdClaim = User.FindFirst("studychat_user_id")?.Value;
                if (!string.IsNullOrEmpty(userIdClaim) && long.TryParse(userIdClaim, out var userId))
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await LinkSessionToUserAsync(userId);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Background session linking failed for user {UserId}", userId);
                        }
                    });
                }
                return LocalRedirect(returnUrl);
            }

            // If for some reason the principal isn't populated yet, explicitly authenticate the cookie scheme.
            var cookieResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (cookieResult.Succeeded && cookieResult.Principal != null)
            {
                HttpContext.User = cookieResult.Principal;
                
                // Link session to user if not already linked (fallback in case OnTicketReceived didn't do it)
                // Do this in background to avoid blocking the redirect (non-critical operation)
                var userIdClaim = cookieResult.Principal.FindFirst("studychat_user_id")?.Value;
                if (!string.IsNullOrEmpty(userIdClaim) && long.TryParse(userIdClaim, out var userId))
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await LinkSessionToUserAsync(userId);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Background session linking failed for user {UserId}", userId);
                        }
                    });
                }
                
                return LocalRedirect(returnUrl);
            }

            _logger.LogWarning(
                "GoogleCallback reached without an authenticated cookie user. TraceId={TraceId}, Failure={Failure}",
                traceId,
                cookieResult.Failure?.Message);

            if (debugAuthEnabled)
            {
                return StatusCode(401, new
                {
                    message = "Not authenticated after Google sign-in. The cookie principal was not established.",
                    traceId,
                    cookieAuth = new
                    {
                        succeeded = cookieResult.Succeeded,
                        failure = cookieResult.Failure?.Message
                    },
                    request = new
                    {
                        method = Request.Method,
                        scheme = Request.Scheme,
                        host = Request.Host.Value,
                        path = Request.Path.Value,
                        queryString = Request.QueryString.Value
                    }
                });
            }

            return RedirectToAction("Login", "Account",
                new { error = $"Google sign-in failed to establish a session. Ref: {traceId}" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception in GoogleCallback. TraceId={TraceId}", traceId);

            if (debugAuthEnabled)
            {
                return StatusCode(500, new
                {
                    message = "Unhandled exception in /Account/GoogleCallback (enable Debug:Auth only temporarily).",
                    traceId,
                    exception = new
                    {
                        type = ex.GetType().FullName,
                        ex.Message,
                        stackTrace = ex.StackTrace
                    }
                });
            }

            return RedirectToAction("Login", "Account",
                new { error = $"Google sign-in crashed on the server. Ref: {traceId}" });
        }
    }

    public async Task<IActionResult> Logout()
    {
        // Capture session ID before signing out (HttpContext might be disposed in background task)
        var sessionId = HttpContext.GetSessionId();
        var serviceProvider = HttpContext.RequestServices;
        
        // Sign out immediately - don't wait for session unlink
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
        // Unlink session from user (set UserId to null) - do in background to avoid blocking redirect
        if (!string.IsNullOrEmpty(sessionId))
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await UnlinkSessionFromUserAsync(sessionId, serviceProvider);
                }
                catch (Exception ex)
                {
                    try
                    {
                        using var errorScope = serviceProvider.CreateScope();
                        var logger = errorScope.ServiceProvider.GetService<ILogger<AccountController>>();
                        logger?.LogWarning(ex, "Background session unlink failed during logout. SessionId={SessionId}", sessionId);
                    }
                    catch { }
                }
            });
        }
        
        return RedirectToAction("Login");
    }

    /// <summary>
    /// Links the current session (from cookie) to the authenticated user.
    /// This is called after successful login to associate the session with the user.
    /// </summary>
    private async Task LinkSessionToUserAsync(long userId)
    {
        try
        {
            // Use extension method to get session ID from HttpContext.Items or cookie
            var sessionId = HttpContext.GetSessionId();
            if (!string.IsNullOrEmpty(sessionId))
            {
                var session = await _dbContext.Sessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId);
                
                if (session != null)
                {
                    session.UserId = userId;
                    session.LastAccessedAt = DateTimeOffset.UtcNow;
                    await _dbContext.SaveChangesAsync();
                    _logger.LogInformation("Linked session {SessionId} to user {UserId}", sessionId, userId);
                }
            }
        }
        catch (Exception ex)
        {
            // Log but don't fail - session linking is not critical
            _logger.LogWarning(ex, "Failed to link session to user {UserId}", userId);
        }
    }

    /// <summary>
    /// Unlinks the current session from the user (sets UserId to null).
    /// This is called during logout.
    /// </summary>
    private async Task UnlinkSessionFromUserAsync(string sessionId, IServiceProvider serviceProvider)
    {
        try
        {
            using var scope = serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var logger = scope.ServiceProvider.GetService<ILogger<AccountController>>();
            
            var session = await dbContext.Sessions
                .FirstOrDefaultAsync(s => s.SessionId == sessionId);
            
            if (session != null)
            {
                session.UserId = null;
                session.LastAccessedAt = DateTimeOffset.UtcNow;
                session.EndedAt = DateTimeOffset.UtcNow; // Mark session as ended
                await dbContext.SaveChangesAsync();
                logger?.LogInformation("Unlinked session {SessionId} from user", sessionId);
            }
            else
            {
                logger?.LogWarning("Session {SessionId} not found in database during logout", sessionId);
            }
        }
        catch (Exception ex)
        {
            // Log but don't fail - session unlinking is not critical
            try
            {
                using var errorScope = serviceProvider.CreateScope();
                var logger = errorScope.ServiceProvider.GetService<ILogger<AccountController>>();
                logger?.LogWarning(ex, "Failed to unlink session {SessionId} from user", sessionId);
            }
            catch { }
        }
    }
}

