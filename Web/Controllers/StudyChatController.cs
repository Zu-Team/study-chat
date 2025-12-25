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
            // Initialize with empty list - if there are no chats, that's fine, not an error
            ViewBag.Chats = new List<Models.Chat>();
            
            try
            {
                var chats = await _chatService.GetChatsForUserAsync(userId.Value);
                ViewBag.Chats = chats ?? new List<Models.Chat>();
                // No chats is normal - don't show error, just show empty list
            }
            catch (PostgresException pgEx) when (pgEx.SqlState == "42P01")
            {
                // 42P01 = undefined_table (e.g., relation "chats" does not exist)
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(pgEx, "Database schema missing (undefined_table). TraceId={TraceId}. Hint={Hint}", traceId, pgEx.MessageText);
                ViewBag.ErrorMessage = $"Database tables are not initialized yet (missing table). Ref: {traceId}";
            }
            catch (PostgresException pgEx)
            {
                // Other PostgreSQL errors - log but don't show to user unless it's critical
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(pgEx, "PostgreSQL error loading chats. TraceId={TraceId}, SqlState={SqlState}", traceId, pgEx.SqlState);
                // Only show error for critical database issues
                if (pgEx.SqlState == "08000" || pgEx.SqlState == "08003" || pgEx.SqlState == "08006") // Connection errors
                {
                    ViewBag.ErrorMessage = $"Database connection error. Ref: {traceId}";
                }
            }
            catch (Microsoft.EntityFrameworkCore.DbUpdateException dbEx)
            {
                // Database update errors - log but don't show for read operations
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(dbEx, "Database update error loading chats. TraceId={TraceId}", traceId);
                // Don't show error - empty list is fine
            }
            catch (Exception ex)
            {
                // Only log actual unexpected errors - don't show error for empty results
                var traceId = HttpContext.TraceIdentifier;
                _logger.LogError(ex, "Unexpected error loading chats. TraceId={TraceId}, UserId={UserId}, ExceptionType={ExceptionType}", 
                    traceId, userId.Value, ex.GetType().Name);
                
                // Only show error for actual critical issues, not for empty results or expected exceptions
                // Empty results should just show "No chats yet" message
                var isExpectedException = ex is System.InvalidOperationException || 
                                         ex is System.ArgumentException ||
                                         ex.Message.Contains("Sequence contains no elements", StringComparison.OrdinalIgnoreCase) ||
                                         ex.Message.Contains("No element", StringComparison.OrdinalIgnoreCase);
                
                if (!isExpectedException)
                {
                    ViewBag.ErrorMessage = $"We couldn't load your chats due to a server error. Ref: {traceId}";
                }
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

