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
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action("GoogleCallback", "Account")
        };
        return Challenge(properties, "Google");
    }

    [AllowAnonymous]
    public async Task<IActionResult> GoogleCallback()
    {
        // Debug: Log all request information
        var debugInfo = new
        {
            Url = Request.Path + Request.QueryString,
            UserAuthenticated = User.Identity?.IsAuthenticated,
            UserAuthType = User.Identity?.AuthenticationType,
            UserClaimsCount = User.Claims?.Count() ?? 0,
            QueryParams = Request.Query.ToDictionary(q => q.Key, q => q.Value.ToString()),
            Cookies = Request.Cookies.Keys.ToList()
        };

        // Try to get the Google authentication result
        var result = await HttpContext.AuthenticateAsync("Google");
        
        // Debug: Log authentication result
        var authDebug = new
        {
            Succeeded = result.Succeeded,
            FailureMessage = result.Failure?.Message,
            PrincipalClaimsCount = result.Principal?.Claims?.Count() ?? 0,
            TicketProperties = result.Properties?.Items?.Keys.ToList()
        };
        
        // If that doesn't work, try reading from the current user (middleware might have already processed it)
        var claims = result.Succeeded ? result.Principal?.Claims : null;
        if (claims == null)
        {
            // Check if user is authenticated with Google scheme
            if (User.Identity?.IsAuthenticated == true && User.Identity.AuthenticationType == "Google")
            {
                claims = User.Claims;
            }
            else
            {
                // Try to authenticate again
                result = await HttpContext.AuthenticateAsync("Google");
                if (!result.Succeeded)
                {
                    // Return debug information in the error
                    var errorDetails = $"Auth failed. Debug: Succeeded={authDebug.Succeeded}, Failure={authDebug.FailureMessage}, UserAuth={debugInfo.UserAuthenticated}, UserType={debugInfo.UserAuthType}, UserClaims={debugInfo.UserClaimsCount}";
                    return RedirectToAction("Login", "Account", new { error = $"Google authentication failed: {errorDetails}" });
                }
                claims = result.Principal?.Claims;
            }
        }

        if (claims == null)
        {
            return RedirectToAction("Login", new { error = "No claims received from Google" });
        }

        // Extract Google claims (Google returns raw JSON keys: "sub", "email", "name")
        var googleSub = claims.FirstOrDefault(c => c.Type == "sub" || c.Type == ClaimTypes.NameIdentifier)?.Value;
        var email = claims.FirstOrDefault(c => c.Type == "email" || c.Type == ClaimTypes.Email)?.Value;
        var name = claims.FirstOrDefault(c => c.Type == "name" || c.Type == ClaimTypes.Name)?.Value;

        if (string.IsNullOrEmpty(googleSub) || string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login", new { error = "Missing required Google claims" });
        }

        // Upsert user in database
        var user = await _userService.UpsertGoogleUserAsync(googleSub, email, name);

        // Create local claims for cookie authentication
        var localClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.FullName ?? user.Email)
        };

        var claimsIdentity = new ClaimsIdentity(localClaims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30)
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        return RedirectToAction("Index", "StudyChat");
    }

    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}

