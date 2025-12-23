using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class StudyChatController : Controller
    {
        // GET: /StudyChat
        public IActionResult Index()
        {
            ViewData["Title"] = "Study Chat";
            return View();
        }
    }
}

