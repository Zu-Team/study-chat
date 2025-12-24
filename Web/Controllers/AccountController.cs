using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Services;

namespace Web.Controllers;

public class AccountController : Controller
{
    private readonly UserService _userService;

    public AccountController(UserService userService)
    {
        _userService = userService;
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
        // RedirectUri is now set in OnTicketReceived event
        // This will redirect to /StudyChat after authentication
        var properties = new AuthenticationProperties
        {
            RedirectUri = "/StudyChat"
        };
        return Challenge(properties, "Google");
    }

    [AllowAnonymous]
    public async Task<IActionResult> GoogleCallback()
    {
        // Try to get the Google authentication result
        var result = await HttpContext.AuthenticateAsync("Google");
        
        if (!result.Succeeded)
        {
            return RedirectToAction("Login", "Account", new { error = $"Google authentication failed: {result.Failure?.Message ?? "Unknown error"}" });
        }

        // Get user info from properties (set in OnTicketReceived event)
        result.Properties?.Items?.TryGetValue("UserId", out var userId);
        result.Properties?.Items?.TryGetValue("UserEmail", out var userEmail);
        result.Properties?.Items?.TryGetValue("UserName", out var userName);

        if (string.IsNullOrEmpty(userId))
        {
            // Fallback: try to get from claims
            var claims = result.Principal?.Claims;
            if (claims != null)
            {
                var googleSub = claims.FirstOrDefault(c => c.Type == "sub" || c.Type == ClaimTypes.NameIdentifier)?.Value;
                var email = claims.FirstOrDefault(c => c.Type == "email" || c.Type == ClaimTypes.Email)?.Value;
                var name = claims.FirstOrDefault(c => c.Type == "name" || c.Type == ClaimTypes.Name)?.Value;

                if (!string.IsNullOrEmpty(googleSub) && !string.IsNullOrEmpty(email))
                {
                    var user = await _userService.UpsertGoogleUserAsync(googleSub, email, name);
                    userId = user.Id.ToString();
                    userEmail = user.Email;
                    userName = user.FullName ?? user.Email;
                }
            }
        }

        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", new { error = "Unable to retrieve user information" });
        }

        // Create local claims for cookie authentication
        var localClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId ?? string.Empty),
            new Claim(ClaimTypes.Email, userEmail ?? string.Empty),
            new Claim(ClaimTypes.Name, userName ?? userEmail ?? string.Empty)
        };

        var claimsIdentity = new ClaimsIdentity(localClaims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Sign in with cookies
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        // Sign out from Google scheme (cleanup)
        await HttpContext.SignOutAsync("Google");

        return RedirectToAction("Index", "StudyChat");
    }

    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}

