using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Services;

namespace Web.Controllers
{
    [Authorize]
    public class StudyChatController : Controller
    {
        private readonly ChatService _chatService;

        public StudyChatController(ChatService chatService)
        {
            _chatService = chatService;
        }

        // GET: /StudyChat?chatId={guid}
        public async Task<IActionResult> Index(Guid? chatId)
        {
            // Get user ID from claims
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return RedirectToAction("Login", "Account");
            }

            // Load all chats for sidebar
            var chats = await _chatService.GetChatsForUserAsync(userId);
            ViewBag.Chats = chats;

            // Load messages if chatId is provided and belongs to user
            List<Models.Message>? messages = null;
            Models.Chat? selectedChat = null;

            if (chatId.HasValue)
            {
                selectedChat = await _chatService.GetChatByIdAsync(chatId.Value, userId);
                if (selectedChat != null)
                {
                    messages = await _chatService.GetMessagesAsync(chatId.Value);
                    ViewBag.SelectedChat = selectedChat;
                    ViewBag.ChatTitle = selectedChat.Name ?? "Untitled Chat";
                }
            }

            ViewBag.Messages = messages ?? new List<Models.Message>();
            ViewBag.HasSelectedChat = selectedChat != null;

            ViewData["Title"] = selectedChat?.Name ?? "Study Chat";
            return View();
        }

        // POST: /StudyChat/NewChat
        [HttpPost]
        public async Task<IActionResult> NewChat()
        {
            // Get user ID from claims
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return RedirectToAction("Login", "Account");
            }

            // Create new chat
            var newChat = await _chatService.CreateNewChatAsync(userId);

            // Redirect to the new chat
            return RedirectToAction("Index", new { chatId = newChat.Id });
        }
    }
}

