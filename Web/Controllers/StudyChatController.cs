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
        private readonly UserService _userService;
        private const string StudyChatUserIdClaim = "studychat_user_id";

        public StudyChatController(ChatService chatService, UserService userService)
        {
            _chatService = chatService;
            _userService = userService;
        }

        private async Task<Guid?> ResolveUserIdAsync()
        {
            // Prefer an explicit app user-id claim (set during Google sign-in)
            var raw =
                User.FindFirst(StudyChatUserIdClaim)?.Value ??
                User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrWhiteSpace(raw) && Guid.TryParse(raw, out var userId))
            {
                return userId;
            }

            // Fallback: if the NameIdentifier is Google's "sub" (not a GUID),
            // resolve our local user by email.
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (!string.IsNullOrWhiteSpace(email))
            {
                var user = await _userService.GetUserByEmailAsync(email);
                if (user != null)
                {
                    return user.Id;
                }
            }

            return null;
        }

        // GET: /StudyChat?chatId={guid}
        public async Task<IActionResult> Index(Guid? chatId)
        {
            var userId = await ResolveUserIdAsync();
            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            // Load all chats for sidebar
            var chats = await _chatService.GetChatsForUserAsync(userId.Value);
            ViewBag.Chats = chats;

            // Load messages if chatId is provided and belongs to user
            List<Models.Message>? messages = null;
            Models.Chat? selectedChat = null;

            if (chatId.HasValue)
            {
                selectedChat = await _chatService.GetChatByIdAsync(chatId.Value, userId.Value);
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
            var userId = await ResolveUserIdAsync();
            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            // Create new chat
            var newChat = await _chatService.CreateNewChatAsync(userId.Value);

            // Redirect to the new chat
            return RedirectToAction("Index", new { chatId = newChat.Id });
        }
    }
}

