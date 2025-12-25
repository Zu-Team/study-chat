using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Npgsql;
using Web.Services;

namespace Web.Controllers
{
    [Authorize]
    public class StudyChatController : Controller
    {
        private readonly ChatService _chatService;
        private readonly UserService _userService;
        private readonly ILogger<StudyChatController> _logger;
        private const string StudyChatUserIdClaim = "studychat_user_id";

        public StudyChatController(ChatService chatService, UserService userService, ILogger<StudyChatController> logger)
        {
            _chatService = chatService;
            _userService = userService;
            _logger = logger;
        }

        private async Task<long?> ResolveUserIdAsync()
        {
            // Prefer an explicit app user-id claim (set during Google sign-in)
            var raw =
                User.FindFirst(StudyChatUserIdClaim)?.Value ??
                User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrWhiteSpace(raw) && long.TryParse(raw, out var userId))
            {
                return userId;
            }

            // Fallback: if the NameIdentifier is Google's "sub" (not a number),
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

        // GET: /StudyChat?chatId={id}
        public async Task<IActionResult> Index(long? chatId)
        {
            var userId = await ResolveUserIdAsync();
            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            // Load all chats for sidebar
            try
            {
                var chats = await _chatService.GetChatsForUserAsync(userId.Value);
                ViewBag.Chats = chats;
            }
            catch (PostgresException pgEx) when (pgEx.SqlState == "42P01")
            {
                // 42P01 = undefined_table (e.g., relation "chats" does not exist)
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(pgEx, "Database schema missing (undefined_table). TraceId={TraceId}. Hint={Hint}", traceId, pgEx.MessageText);
                ViewBag.ErrorMessage = $"Database tables are not initialized yet (missing table). Ref: {traceId}";
                ViewBag.Chats = new List<Models.Chat>();
            }
            catch (Exception ex)
            {
                // If DB tables are missing/migrations not applied, this throws and looks like "auth failed"
                // because production redirects errors to Login. Instead, render the page with an error banner.
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(ex, "Failed to load chats. TraceId={TraceId}", traceId);
                ViewBag.ErrorMessage = $"We couldn't load your chats due to a server error. Ref: {traceId}";
                ViewBag.Chats = new List<Models.Chat>();
            }

            // Load messages if chatId is provided and belongs to user
            List<Models.Message>? messages = null;
            Models.Chat? selectedChat = null;

            if (chatId.HasValue)
            {
                try
                {
                    selectedChat = await _chatService.GetChatByIdAsync(chatId.Value, userId.Value);
                    if (selectedChat != null)
                    {
                        messages = await _chatService.GetMessagesAsync(chatId.Value);
                        ViewBag.SelectedChat = selectedChat;
                        ViewBag.ChatTitle = selectedChat.Name ?? "Untitled Chat";
                    }
                }
                catch (Exception ex)
                {
                    var traceId = HttpContext.TraceIdentifier;
                    _logger.LogError(ex, "Failed to load selected chat/messages. TraceId={TraceId}, ChatId={ChatId}", traceId, chatId.Value);
                    ViewBag.ErrorMessage = $"We couldn't load this chat due to a server error. Ref: {traceId}";
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
            Models.Chat newChat;
            try
            {
                newChat = await _chatService.CreateNewChatAsync(userId.Value);
            }
            catch (Exception ex)
            {
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(ex, "Failed to create new chat. TraceId={TraceId}", traceId);
                return RedirectToAction("Index", new { error = $"Couldn't create chat due to a server error. Ref: {traceId}" });
            }

            // Redirect to the new chat
            return RedirectToAction("Index", new { chatId = newChat.Id });
        }
    }
}

