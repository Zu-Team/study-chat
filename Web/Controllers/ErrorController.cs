using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Models;

namespace Web.Controllers;

[AllowAnonymous]
[Route("Error")]
public class ErrorController : Controller
{
    [HttpGet("")]
    public IActionResult Index()
    {
        var model = new ErrorViewModel
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
        };

        return View("~/Views/Shared/Error.cshtml", model);
    }
}

