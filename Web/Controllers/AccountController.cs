using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Web.Services;

namespace Web.Controllers;

public class AccountController : Controller
{
    private readonly UserService _userService;
    private readonly ILogger<AccountController> _logger;
    private readonly IConfiguration _configuration;

    public AccountController(UserService userService, ILogger<AccountController> logger, IConfiguration configuration)
    {
        _userService = userService;
        _logger = logger;
        _configuration = configuration;
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Login(string email, string password)
    {
        // TODO: Implement local authentication logic
        // For now, this is just a placeholder
        return RedirectToAction("Index", "StudyChat");
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
            _logger.LogError(ex, "Database error while creating local account. TraceId={TraceId}, Email={Email}", traceId, email);
            ModelState.AddModelError(string.Empty, $"Database error while creating the account. Ref: {traceId}");
            return View();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while creating local account. TraceId={TraceId}, Email={Email}", traceId, email);
            ModelState.AddModelError(string.Empty, $"Unexpected server error while creating the account. Ref: {traceId}");
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
        return Challenge(properties, "Google");
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
                return LocalRedirect(returnUrl);
            }

            // If for some reason the principal isn't populated yet, explicitly authenticate the cookie scheme.
            var cookieResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (cookieResult.Succeeded && cookieResult.Principal != null)
            {
                HttpContext.User = cookieResult.Principal;
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
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}

