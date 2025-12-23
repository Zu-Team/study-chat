using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class PController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
