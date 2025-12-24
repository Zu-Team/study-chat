using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
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
    public IActionResult Register(string email, string password, string confirmPassword)
    {
        // TODO: Implement registration logic
        // For now, this is just a placeholder
        return RedirectToAction("Login");
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
        // Set the redirect URI so after Google auth, we go to GoogleCallback which will redirect to StudyChat
        var properties = new AuthenticationProperties { RedirectUri = "/Account/GoogleCallback" };
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
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Index", "StudyChat");
            }

            // If for some reason the principal isn't populated yet, explicitly authenticate the cookie scheme.
            var cookieResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (cookieResult.Succeeded && cookieResult.Principal != null)
            {
                HttpContext.User = cookieResult.Principal;
                return RedirectToAction("Index", "StudyChat");
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

