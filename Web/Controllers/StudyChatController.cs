using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Web.Services;
using Web.Data;
using Web.Extensions;

namespace Web.Controllers
{
    [Authorize]
    public class StudyChatController : Controller
    {
        private readonly ChatService _chatService;
        private readonly UserService _userService;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<StudyChatController> _logger;
        private const string StudyChatUserIdClaim = "studychat_user_id";
        private const string SessionIdCookieName = "studychat_session_id";

        public StudyChatController(ChatService chatService, UserService userService, ApplicationDbContext dbContext, ILogger<StudyChatController> logger)
        {
            _chatService = chatService;
            _userService = userService;
            _dbContext = dbContext;
            _logger = logger;
        }

        /// <summary>
        /// Resolves user ID from session ID cookie.
        /// Gets session ID from cookie -> looks up session in DB -> gets user_id from session.
        /// </summary>
        private async Task<long?> ResolveUserIdFromSessionAsync()
        {
            // Get session ID from cookie
            var sessionId = HttpContext.GetSessionId();
            if (string.IsNullOrEmpty(sessionId))
            {
                _logger.LogWarning("No session ID found in cookie");
                return null;
            }

            try
            {
                // Look up session in database
                var session = await _dbContext.Sessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId);

                if (session == null)
                {
                    _logger.LogWarning("Session not found in database. SessionId={SessionId}", sessionId);
                    return null;
                }

                // Get user_id from session (foreign key)
                if (session.UserId.HasValue)
                {
                    _logger.LogInformation("Resolved user ID {UserId} from session {SessionId}", session.UserId.Value, sessionId);
                    return session.UserId.Value;
                }
                else
                {
                    // Session exists but user is not logged in (anonymous session)
                    _logger.LogInformation("Session {SessionId} exists but user_id is null (anonymous user)", sessionId);
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resolving user ID from session. SessionId={SessionId}", sessionId);
                return null;
            }
        }

        /// <summary>
        /// Fallback method: Resolves user ID from authentication claims (for backward compatibility)
        /// </summary>
        private async Task<long?> ResolveUserIdFromClaimsAsync()
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

        /// <summary>
        /// Resolves user ID - tries session-based first, then falls back to claims
        /// </summary>
        private async Task<long?> ResolveUserIdAsync()
        {
            // First try: Get user ID from session (session-based authentication)
            var userIdFromSession = await ResolveUserIdFromSessionAsync();
            if (userIdFromSession.HasValue)
            {
                return userIdFromSession;
            }

            // Fallback: Get user ID from authentication claims
            return await ResolveUserIdFromClaimsAsync();
        }

        // GET: /StudyChat?chatId={id}
        public async Task<IActionResult> Index(long? chatId)
        {
            // Step 1: Get session ID from cookie
            var sessionId = HttpContext.GetSessionId();
            
            // Step 2: Check if session ID exists
            if (string.IsNullOrEmpty(sessionId))
            {
                _logger.LogWarning("No session ID found in cookie. Redirecting to login.");
                return RedirectToAction("Login", "Account");
            }

            // Step 3: Look up session in database (use AsNoTracking for read-only query)
            Models.Session? session = null;
            try
            {
                session = await _dbContext.Sessions
                    .AsNoTracking()
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error looking up session in database. SessionId={SessionId}", sessionId);
                return RedirectToAction("Login", "Account");
            }

            // Step 4: Check if session exists
            if (session == null)
            {
                _logger.LogWarning("Session not found in database. SessionId={SessionId}. Redirecting to login.", sessionId);
                return RedirectToAction("Login", "Account");
            }

            // Step 5: Check if user_id (foreign key) is null
            if (!session.UserId.HasValue)
            {
                // Session exists but user_id is null (user not logged in)
                _logger.LogInformation("Session {SessionId} exists but user_id is null (anonymous user). Redirecting to login.", sessionId);
                return RedirectToAction("Login", "Account");
            }

            // Step 6: User is logged in (user_id is not null) - allow access to study page
            var userId = session.UserId.Value;
            _logger.LogInformation("User {UserId} authenticated via session {SessionId}. Allowing access to study page.", userId, sessionId);

            // Load all chats for sidebar using user_id from session
            // Initialize with empty list - if there are no chats, that's fine, not an error
            ViewBag.Chats = new List<Models.Chat>();
            ViewBag.UserId = userId; // Pass user ID to view for debugging if needed
            
            try
            {
                var chats = await _chatService.GetChatsForUserAsync(userId);
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
                    traceId, userId, ex.GetType().Name);
                
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
                    selectedChat = await _chatService.GetChatByIdAsync(chatId.Value, userId);
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
        public async Task<IActionResult> NewChat(string? chatName)
        {
            // Step 1: Get session ID from cookie
            var sessionId = HttpContext.GetSessionId();
            
            // Step 2: Check if session ID exists
            if (string.IsNullOrEmpty(sessionId))
            {
                _logger.LogWarning("No session ID found in cookie. Redirecting to login.");
                return RedirectToAction("Login", "Account");
            }

            // Step 3: Look up session in database (use AsNoTracking for read-only query)
            Models.Session? session = null;
            try
            {
                session = await _dbContext.Sessions
                    .AsNoTracking()
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error looking up session in database. SessionId={SessionId}", sessionId);
                return RedirectToAction("Login", "Account");
            }

            // Step 4: Check if session exists
            if (session == null)
            {
                _logger.LogWarning("Session not found in database. SessionId={SessionId}. Redirecting to login.", sessionId);
                return RedirectToAction("Login", "Account");
            }

            // Step 5: Check if user_id (foreign key) is null
            if (!session.UserId.HasValue)
            {
                // Session exists but user_id is null (user not logged in)
                _logger.LogInformation("Session {SessionId} exists but user_id is null (anonymous user). Redirecting to login.", sessionId);
                return RedirectToAction("Login", "Account");
            }

            // Step 6: User is logged in (user_id is not null) - proceed
            var userId = session.UserId.Value;

            // Create new chat with provided name
            Models.Chat newChat;
            try
            {
                newChat = await _chatService.CreateNewChatAsync(userId, chatName);
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

