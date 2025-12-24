using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Web.Controllers;

public class AccountController : Controller
{
    public AccountController() { }

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
        // The Google handler completes on /signin-google and should sign the user into the Cookie scheme
        // (we do this in Program.cs via OnTicketReceived). This endpoint should only verify cookie auth.
        var cookieResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (cookieResult.Succeeded && cookieResult.Principal?.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "StudyChat");
        }

        var logger = HttpContext.RequestServices.GetRequiredService<ILogger<AccountController>>();
        var failure = cookieResult.Failure?.Message ?? "No auth cookie found after Google sign-in.";
        logger.LogError("GoogleCallback reached without a valid auth cookie. Failure: {Failure}", failure);

        // Common dev cause: running over HTTP while cookies are configured as Secure-only.
        return RedirectToAction("Login", "Account", new
        {
            error = "Sign-in succeeded but no auth cookie was created. If you're developing, run the HTTPS profile (or ensure cookie SecurePolicy isn't Always on HTTP)."
        });
    }

    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}

