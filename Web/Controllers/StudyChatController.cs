using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System.Text;
using System.Text.Json;
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
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private const string StudyChatUserIdClaim = "studychat_user_id";
        private const string SessionIdCookieName = "studychat_session_id";

        public StudyChatController(ChatService chatService, UserService userService, ApplicationDbContext dbContext, ILogger<StudyChatController> logger, IConfiguration configuration, IHttpClientFactory httpClientFactory)
        {
            _chatService = chatService;
            _userService = userService;
            _dbContext = dbContext;
            _logger = logger;
            _configuration = configuration;
            // Use named HttpClient configured in Program.cs (handles SSL in development)
            _httpClient = httpClientFactory.CreateClient("AiWebhook");
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
                    .AsNoTracking() // Read-only query
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
            // Resolve user ID - try session first, then fall back to cookie authentication
            long? userId = null;
            
            // Step 1: Try to get user ID from session (session-based authentication)
            // SECURITY: Session is PRIMARY source of truth - never override with cookie if session has user_id
            var sessionId = HttpContext.GetSessionId();
            Models.Session? session = null;
            
            if (!string.IsNullOrEmpty(sessionId))
            {
                try
                {
                    session = await _dbContext.Sessions
                        .AsNoTracking()
                        .FirstOrDefaultAsync(s => s.SessionId == sessionId);
                    
                    if (session != null && session.UserId.HasValue)
                    {
                        userId = session.UserId.Value;
                        _logger.LogInformation("User {UserId} authenticated via session {SessionId}", userId, sessionId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error looking up session in database. SessionId={SessionId}", sessionId);
                }
            }
            
            // Step 2: Fallback - get user ID from cookie authentication claims
            // SECURITY: Only use cookie if session doesn't have a user_id
            // This prevents mixing users when session belongs to one user but cookie belongs to another
            if (!userId.HasValue)
            {
                var cookieUserId = await ResolveUserIdFromClaimsAsync();
                if (cookieUserId.HasValue)
                {
                    _logger.LogInformation("User {UserId} authenticated via cookie claims (session had no user_id)", cookieUserId.Value);
                    
                    // If we have a session but it's not linked, link it now (SYNCHRONOUSLY to prevent race conditions)
                    if (session != null && !session.UserId.HasValue)
                    {
                        try
                        {
                            // Use tracking context to update session
                            var trackedSession = await _dbContext.Sessions
                                .FirstOrDefaultAsync(s => s.SessionId == sessionId);
                            
                            if (trackedSession != null && !trackedSession.UserId.HasValue)
                            {
                                trackedSession.UserId = cookieUserId.Value;
                                trackedSession.LastAccessedAt = DateTimeOffset.UtcNow;
                                await _dbContext.SaveChangesAsync();
                                _logger.LogInformation("Linked session {SessionId} to user {UserId} during Index access", sessionId, cookieUserId.Value);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Failed to link session during Index access. SessionId={SessionId}, UserId={UserId}", 
                                sessionId, cookieUserId.Value);
                        }
                    }
                    
                    userId = cookieUserId;
                }
            }
            else if (session != null && session.UserId.HasValue)
            {
                // SECURITY: Session has user ID - verify cookie claims match (if they exist) for logging
                // We still use session user ID as source of truth, but log mismatches
                var cookieUserId = await ResolveUserIdFromClaimsAsync();
                if (cookieUserId.HasValue && cookieUserId.Value != userId.Value)
                {
                    _logger.LogWarning("SECURITY: User ID mismatch between session and cookie! SessionUserId={SessionUserId}, CookieUserId={CookieUserId}, SessionId={SessionId}. " +
                        "Using session user ID as source of truth.", userId.Value, cookieUserId.Value, sessionId);
                    // Use session user ID (session is primary source of truth)
                }
            }
            
            // Step 3: If no user ID found, redirect to login
            if (!userId.HasValue)
            {
                _logger.LogWarning("No user ID found via session or cookie authentication. Redirecting to login.");
                return RedirectToAction("Login", "Account");
            }
            
            // Step 4: User is authenticated - allow access to study page
            var finalUserId = userId.Value;

            // SECURITY: Double-check user ID from session to prevent mix-ups
            // Verify the session belongs to this user
            // session variable is already declared above, so we just verify it matches
            if (!string.IsNullOrEmpty(sessionId) && session != null && session.UserId.HasValue)
            {
                if (session.UserId.Value != finalUserId)
                {
                    // Session user ID doesn't match resolved user ID - security issue!
                    _logger.LogWarning("SECURITY: User ID mismatch! SessionUserId={SessionUserId}, ResolvedUserId={ResolvedUserId}, SessionId={SessionId}", 
                        session.UserId.Value, finalUserId, sessionId);
                    // Use session's user ID as the source of truth
                    finalUserId = session.UserId.Value;
                    _logger.LogInformation("Using session's user ID {UserId} for authorization", finalUserId);
                }
            }

            // SECURITY: Check chat authorization FIRST, before loading any data
            // If chatId is provided in URL, verify it belongs to the user IMMEDIATELY
            if (chatId.HasValue)
            {
                try
                {
                    // CRITICAL: Verify chat ownership BEFORE loading any other data
                    var chatExists = await _dbContext.Chats
                        .AsNoTracking()
                        .AnyAsync(c => c.Id == chatId.Value && c.UserId == finalUserId);
                    
                    if (!chatExists)
                    {
                        // Chat doesn't exist or doesn't belong to this user - SECURITY VIOLATION
                        var traceId = HttpContext.TraceIdentifier;
                        _logger.LogWarning("SECURITY: Unauthorized chat access attempt blocked. UserId={UserId}, ChatId={ChatId}, SessionId={SessionId}, TraceId={TraceId}", 
                            finalUserId, chatId.Value, sessionId, traceId);
                        
                        // Redirect immediately - don't load any data
                        return RedirectToAction("Index", "StudyChat");
                    }
                    
                    _logger.LogInformation("Chat authorization verified. UserId={UserId}, ChatId={ChatId}, SessionId={SessionId}", 
                        finalUserId, chatId.Value, sessionId);
                }
                catch (Exception ex)
                {
                    var traceId = HttpContext.TraceIdentifier;
                    _logger.LogError(ex, "Error checking chat authorization. TraceId={TraceId}, ChatId={ChatId}, UserId={UserId}", 
                        traceId, chatId.Value, finalUserId);
                    // On error, redirect to be safe
                    return RedirectToAction("Index", "StudyChat");
                }
            }

            // Load all chats for sidebar using user_id
            // Initialize with empty list - if there are no chats, that's fine, not an error
            ViewBag.Chats = new List<Models.Chat>();
            ViewBag.UserId = finalUserId; // Pass user ID to view for debugging if needed
            
            try
            {
                // SECURITY: Explicitly filter chats by user ID - add logging for debugging
                var chats = await _chatService.GetChatsForUserAsync(finalUserId);
                _logger.LogInformation("Loaded {Count} chats for user {UserId}. SessionId={SessionId}", 
                    chats?.Count ?? 0, finalUserId, sessionId);
                
                // SECURITY: Double-check all chats belong to this user (defense in depth)
                if (chats != null && chats.Any(c => c.UserId != finalUserId))
                {
                    _logger.LogError("SECURITY VIOLATION: Found chats that don't belong to user {UserId}! Filtering out unauthorized chats.", finalUserId);
                    chats = chats.Where(c => c.UserId == finalUserId).ToList();
                }
                
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
                    traceId, finalUserId, ex.GetType().Name);
                
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
                    // Authorization already verified above - safe to load chat
                    selectedChat = await _chatService.GetChatByIdAsync(chatId.Value, finalUserId);
                    
                    // Defense in depth: Double-check (should never fail if authorization above worked)
                    if (selectedChat == null || selectedChat.UserId != finalUserId)
                    {
                        var traceId = HttpContext.TraceIdentifier;
                        _logger.LogError("SECURITY VIOLATION: Chat authorization check failed after initial verification! UserId={UserId}, ChatId={ChatId}, TraceId={TraceId}", 
                            finalUserId, chatId.Value, traceId);
                        return RedirectToAction("Index", "StudyChat");
                    }
                    
                    // Chat belongs to user - load messages (with authorization check)
                    messages = await _chatService.GetMessagesAsync(chatId.Value, finalUserId);
                    ViewBag.SelectedChat = selectedChat;
                    ViewBag.ChatTitle = selectedChat.Name ?? "Untitled Chat";
                }
                catch (Exception ex)
                {
                    var traceId = HttpContext.TraceIdentifier;
                    _logger.LogError(ex, "Failed to load selected chat/messages. TraceId={TraceId}, ChatId={ChatId}, UserId={UserId}", 
                        traceId, chatId.Value, finalUserId);
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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> NewChat(string? chatName)
        {
            var traceId = HttpContext.TraceIdentifier;
            
            try
            {
                // Resolve user ID - try session first, then fall back to cookie authentication
                long? userId = null;
                
                // Step 1: Try to get user ID from session (session-based authentication)
                var sessionId = HttpContext.GetSessionId();
                if (!string.IsNullOrEmpty(sessionId))
                {
                    try
                    {
                        var session = await _dbContext.Sessions
                            .AsNoTracking()
                            .FirstOrDefaultAsync(s => s.SessionId == sessionId);
                        
                        if (session != null && session.UserId.HasValue)
                        {
                            userId = session.UserId.Value;
                            _logger.LogInformation("User {UserId} authenticated via session {SessionId} for NewChat", userId, sessionId);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error looking up session in database for NewChat. SessionId={SessionId}", sessionId);
                    }
                }
                
                // Step 2: Fallback - get user ID from cookie authentication claims
                if (!userId.HasValue)
                {
                    userId = await ResolveUserIdFromClaimsAsync();
                    if (userId.HasValue)
                    {
                        _logger.LogInformation("User {UserId} authenticated via cookie claims for NewChat", userId.Value);
                    }
                }
                
                // Step 3: If no user ID found, redirect to login
                if (!userId.HasValue)
                {
                    _logger.LogWarning("No user ID found via session or cookie authentication for NewChat. Redirecting to login.");
                    return RedirectToAction("Login", "Account");
                }
                
                // Step 4: Create new chat with provided name
                Models.Chat newChat;
                try
                {
                    newChat = await _chatService.CreateNewChatAsync(userId.Value, chatName);
                    _logger.LogInformation("Created new chat {ChatId} for user {UserId}", newChat.Id, userId.Value);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to create new chat. TraceId={TraceId}, UserId={UserId}", traceId, userId.Value);
                    return RedirectToAction("Index", new { error = $"Couldn't create chat due to a server error. Ref: {traceId}" });
                }

                // Redirect to the new chat
                return RedirectToAction("Index", new { chatId = newChat.Id });
            }
            catch (Exception ex)
            {
                // Catch any unhandled exceptions to prevent 502 errors
                _logger.LogError(ex, "Unhandled exception in NewChat. TraceId={TraceId}, ExceptionType={ExceptionType}", 
                    traceId, ex.GetType().Name);
                return RedirectToAction("Index", new { error = $"An unexpected error occurred. Ref: {traceId}" });
            }
        }

        // POST: /StudyChat/SendMessage
        [HttpPost]
        [IgnoreAntiforgeryToken] // API endpoint - anti-forgery handled by [Authorize] attribute
        public async Task<IActionResult> SendMessage([FromBody] SendMessageRequest request)
        {
            var traceId = HttpContext.TraceIdentifier;
            
            try
            {
                // Validate request
                if (string.IsNullOrWhiteSpace(request?.Message))
                {
                    _logger.LogWarning("SendMessage: Empty message received. TraceId={TraceId}", traceId);
                    return BadRequest(new { error = "Message is required", traceId });
                }

                // Resolve user ID
                var userId = await ResolveUserIdAsync();
                if (!userId.HasValue)
                {
                    _logger.LogWarning("SendMessage: User not authenticated. TraceId={TraceId}", traceId);
                    return Unauthorized(new { error = "User not authenticated", traceId });
                }

                // Get or create chat
                Models.Chat chat;
                if (request.ChatId.HasValue)
                {
                    // SECURITY: Verify chat belongs to current user using session-based authorization
                    // userId.Value is safe here because we checked userId.HasValue above
                    chat = await _chatService.GetChatByIdAsync(request.ChatId.Value, userId.Value);
                    if (chat == null)
                    {
                        _logger.LogWarning("SendMessage: Unauthorized chat access attempt. ChatId={ChatId}, UserId={UserId}, TraceId={TraceId}", 
                            request.ChatId.Value, userId.Value, traceId);
                        return Unauthorized(new { error = "Chat not found or you don't have access to it", traceId });
                    }
                    
                    // Additional security check: Verify chat.UserId matches current user
                    if (chat.UserId != userId.Value)
                    {
                        _logger.LogWarning("SendMessage: Chat ownership mismatch. ChatUserId={ChatUserId}, CurrentUserId={CurrentUserId}, ChatId={ChatId}, TraceId={TraceId}", 
                            chat.UserId, userId.Value, request.ChatId.Value, traceId);
                        return Unauthorized(new { error = "You don't have access to this chat", traceId });
                    }
                }
                else
                {
                    // Create new chat
                    chat = await _chatService.CreateNewChatAsync(userId.Value, "New Chat");
                    _logger.LogInformation("SendMessage: Created new chat {ChatId} for user {UserId}. TraceId={TraceId}", 
                        chat.Id, userId.Value, traceId);
                }

                // Save user message to database
                var userMessage = new Models.Message
                {
                    ChatId = chat.Id,
                    SenderId = userId.Value,
                    Content = request.Message.Trim(),
                    CreatedAt = DateTimeOffset.UtcNow
                };

                _dbContext.Messages.Add(userMessage);
                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("SendMessage: Saved user message {MessageId} to chat {ChatId}. TraceId={TraceId}", 
                    userMessage.Id, chat.Id, traceId);

                // Get webhook URL from configuration
                var webhookUrl = _configuration["AiWebhook:Url"];
                if (string.IsNullOrEmpty(webhookUrl))
                {
                    _logger.LogError("AI Webhook URL is not configured. TraceId={TraceId}", traceId);
                    return StatusCode(500, new { error = "AI service is not configured", traceId });
                }

                _logger.LogInformation("SendMessage: Starting. TraceId={TraceId}, WebhookUrl={WebhookUrl}, MessageLength={Length}, ChatId={ChatId}", 
                    traceId, webhookUrl, request.Message.Length, chat.Id);

                // Get user's AI customization (if exists)
                string? customizeText = null;
                try
                {
                    var customization = await _dbContext.Customizes
                        .AsNoTracking()
                        .FirstOrDefaultAsync(c => c.UserId == userId.Value);
                    
                    if (customization != null && !string.IsNullOrWhiteSpace(customization.Text))
                    {
                        customizeText = customization.Text;
                        _logger.LogInformation("SendMessage: Found customization for user {UserId}. Length={Length}, TraceId={TraceId}", 
                            userId.Value, customizeText.Length, traceId);
                    }
                    else
                    {
                        _logger.LogInformation("SendMessage: No customization found for user {UserId}. TraceId={TraceId}", 
                            userId.Value, traceId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "SendMessage: Failed to load customization for user {UserId}. Continuing without customization. TraceId={TraceId}", 
                        userId.Value, traceId);
                    // Continue without customization - not critical
                }

                // Prepare request to webhook - n8n webhook receives the entire JSON body
                // Include all necessary information for n8n to insert into database
                // Based on workflow: AI Agent uses "={{ $json }}" so it receives the full request body
                var webhookRequest = new
                {
                    message = request.Message.Trim(),
                    text = request.Message.Trim(), // Some AI agents expect "text" field
                    input = request.Message.Trim(), // Alternative field name
                    type = request.Type ?? "normal", // Message type: "normal" or "quiz"
                    customize = customizeText ?? string.Empty, // User's AI customization instructions
                    chatId = chat.Id, // Chat ID for database insertion
                    userId = userId.Value, // User ID for database insertion
                    messageId = userMessage.Id, // User message ID (already saved)
                    timestamp = DateTimeOffset.UtcNow,
                    chatName = chat.Name, // Optional: chat name
                    sessionId = HttpContext.GetSessionId() // Session ID if available
                };

                var jsonContent = JsonSerializer.Serialize(webhookRequest);
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                _logger.LogInformation("SendMessage: Request payload. TraceId={TraceId}, Payload={Payload}", 
                    traceId, jsonContent);

                // Call webhook
                _logger.LogInformation("SendMessage: Calling webhook. TraceId={TraceId}, Url={Url}", traceId, webhookUrl);
                var response = await _httpClient.PostAsync(webhookUrl, content);

                _logger.LogInformation("SendMessage: Webhook response received. TraceId={TraceId}, StatusCode={StatusCode}, Headers={Headers}", 
                    traceId, response.StatusCode, string.Join(", ", response.Headers.Select(h => $"{h.Key}={string.Join(",", h.Value)}")));

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("SendMessage: Webhook error. TraceId={TraceId}, Status={Status}, Response={Response}", 
                        traceId, response.StatusCode, errorContent);
                    return StatusCode((int)response.StatusCode, new { 
                        error = "AI service error", 
                        statusCode = (int)response.StatusCode,
                        details = errorContent,
                        traceId 
                    });
                }

                // Read AI response
                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("SendMessage: Response content received. TraceId={TraceId}, Length={Length}, Content={Content}", 
                    traceId, responseContent.Length, responseContent);

                // Parse response - n8n AI Agent typically returns the response in the output
                // The response structure from n8n AI Agent might be nested
                string aiMessage;
                try
                {
                    var responseJson = JsonSerializer.Deserialize<JsonElement>(responseContent);
                    _logger.LogInformation("SendMessage: Parsing JSON response. TraceId={TraceId}, JsonKeys={Keys}", 
                        traceId, string.Join(", ", responseJson.EnumerateObject().Select(p => p.Name)));
                    
                    // Try to find the AI response in common n8n output formats
                    // n8n AI Agent might return: { output: "...", text: "...", response: "...", data: {...} }
                    if (responseJson.TryGetProperty("output", out var outputField))
                    {
                        if (outputField.ValueKind == JsonValueKind.String)
                            aiMessage = outputField.GetString() ?? responseContent;
                        else if (outputField.ValueKind == JsonValueKind.Object)
                        {
                            // Try to find text/response in nested object
                            if (outputField.TryGetProperty("text", out var textField))
                                aiMessage = textField.GetString() ?? responseContent;
                            else if (outputField.TryGetProperty("response", out var responseField))
                                aiMessage = responseField.GetString() ?? responseContent;
                            else
                                aiMessage = outputField.ToString();
                        }
                        else
                            aiMessage = outputField.ToString();
                    }
                    else if (responseJson.TryGetProperty("text", out var textField))
                        aiMessage = textField.GetString() ?? responseContent;
                    else if (responseJson.TryGetProperty("response", out var responseField))
                        aiMessage = responseField.GetString() ?? responseContent;
                    else if (responseJson.TryGetProperty("message", out var messageField))
                        aiMessage = messageField.GetString() ?? responseContent;
                    else if (responseJson.TryGetProperty("data", out var dataField))
                    {
                        if (dataField.ValueKind == JsonValueKind.String)
                            aiMessage = dataField.GetString() ?? responseContent;
                        else if (dataField.ValueKind == JsonValueKind.Object && dataField.TryGetProperty("text", out var dataText))
                            aiMessage = dataText.GetString() ?? responseContent;
                        else
                            aiMessage = dataField.ToString();
                    }
                    else if (responseJson.TryGetProperty("json", out var jsonField))
                    {
                        // n8n sometimes wraps output in "json" property
                        if (jsonField.ValueKind == JsonValueKind.String)
                            aiMessage = jsonField.GetString() ?? responseContent;
                        else if (jsonField.ValueKind == JsonValueKind.Object)
                        {
                            if (jsonField.TryGetProperty("text", out var jsonText))
                                aiMessage = jsonText.GetString() ?? responseContent;
                            else if (jsonField.TryGetProperty("output", out var jsonOutput))
                                aiMessage = jsonOutput.GetString() ?? responseContent;
                            else
                                aiMessage = jsonField.ToString();
                        }
                        else
                            aiMessage = jsonField.ToString();
                    }
                    else
                    {
                        // If it's an array, try first element
                        if (responseJson.ValueKind == JsonValueKind.Array && responseJson.GetArrayLength() > 0)
                        {
                            var firstItem = responseJson[0];
                            if (firstItem.TryGetProperty("json", out var firstJson))
                            {
                                if (firstJson.TryGetProperty("output", out var firstOutput))
                                    aiMessage = firstOutput.GetString() ?? responseContent;
                                else if (firstJson.TryGetProperty("text", out var firstText))
                                    aiMessage = firstText.GetString() ?? responseContent;
                                else
                                    aiMessage = firstJson.ToString();
                            }
                            else
                                aiMessage = firstItem.ToString();
                        }
                        else
                        {
                            // Fallback: return formatted JSON
                            aiMessage = JsonSerializer.Serialize(responseJson, new JsonSerializerOptions { WriteIndented = false });
                        }
                    }
                    
                    _logger.LogInformation("SendMessage: Extracted AI message. TraceId={TraceId}, MessageLength={Length}", 
                        traceId, aiMessage.Length);
                }
                catch (JsonException jsonEx)
                {
                    _logger.LogWarning(jsonEx, "SendMessage: Failed to parse JSON response, using raw content. TraceId={TraceId}", traceId);
                    aiMessage = responseContent;
                }
                catch (Exception parseEx)
                {
                    _logger.LogWarning(parseEx, "SendMessage: Error parsing response, using raw content. TraceId={TraceId}", traceId);
                    aiMessage = responseContent;
                }

                // Return success with AI response
                _logger.LogInformation("SendMessage: Success. TraceId={TraceId}, ResponseLength={Length}", traceId, aiMessage.Length);
                return Ok(new 
                { 
                    success = true, 
                    userMessage = request.Message.Trim(),
                    aiMessage = aiMessage,
                    chatId = chat.Id,
                    messageId = userMessage.Id,
                    traceId = traceId,
                    debug = new
                    {
                        webhookUrl = webhookUrl,
                        responseLength = responseContent.Length,
                        rawResponse = responseContent.Substring(0, Math.Min(500, responseContent.Length)) // First 500 chars for debugging
                    }
                });
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogError(ex, "SendMessage: Request timed out. TraceId={TraceId}, Timeout={Timeout}", 
                    traceId, _httpClient.Timeout);
                return StatusCode(504, new { error = "AI service request timed out. Please try again.", traceId });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "SendMessage: HTTP error. TraceId={TraceId}, Message={Message}, InnerException={InnerException}, StackTrace={StackTrace}", 
                    traceId, ex.Message, ex.InnerException?.Message, ex.StackTrace);
                
                // Check if it's an SSL certificate error
                if (ex.Message.Contains("certificate", StringComparison.OrdinalIgnoreCase) || 
                    ex.Message.Contains("SSL", StringComparison.OrdinalIgnoreCase) ||
                    ex.InnerException?.Message?.Contains("certificate", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return StatusCode(500, new { error = "SSL certificate validation failed. Please check webhook certificate.", traceId });
                }
                
                return StatusCode(500, new { error = $"Failed to connect to AI service: {ex.Message}", traceId, details = ex.InnerException?.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SendMessage: Unexpected error. TraceId={TraceId}, ExceptionType={ExceptionType}, Message={Message}, StackTrace={StackTrace}", 
                    traceId, ex.GetType().Name, ex.Message, ex.StackTrace);
                return StatusCode(500, new { 
                    error = $"Failed to get AI response: {ex.Message}", 
                    traceId,
                    exceptionType = ex.GetType().Name,
                    innerException = ex.InnerException?.Message
                });
            }
        }

        // GET: /StudyChat/GetCustomizeAI
        [HttpGet]
        public async Task<IActionResult> GetCustomizeAI()
        {
            var traceId = HttpContext.TraceIdentifier;
            
            try
            {
                var userId = await ResolveUserIdAsync();
                if (!userId.HasValue)
                {
                    _logger.LogWarning("GetCustomizeAI: User not authenticated. TraceId={TraceId}", traceId);
                    return Unauthorized(new { error = "User not authenticated", traceId });
                }

                var customize = await _dbContext.Customizes
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.UserId == userId.Value);

                if (customize != null)
                {
                    return Ok(new { text = customize.Text, traceId });
                }
                else
                {
                    return Ok(new { text = "", traceId });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetCustomizeAI: Unhandled exception. TraceId={TraceId}", traceId);
                return StatusCode(500, new { error = $"An unexpected server error occurred: {ex.Message}", traceId });
            }
        }

        // GET: /StudyChat/GetQuiz?chatId={id}
        // GET: /StudyChat/GetMessages?chatId={id}
        [HttpGet]
        public async Task<IActionResult> GetMessages(long? chatId)
        {
            var traceId = HttpContext.TraceIdentifier;
            
            try
            {
                if (!chatId.HasValue)
                {
                    return BadRequest(new { error = "chatId is required", traceId });
                }

                var userId = await ResolveUserIdAsync();
                if (!userId.HasValue)
                {
                    _logger.LogWarning("GetMessages: User not authenticated. TraceId={TraceId}", traceId);
                    return Unauthorized(new { error = "User not authenticated", traceId });
                }

                // SECURITY: Verify chat belongs to user
                var chat = await _chatService.GetChatByIdAsync(chatId.Value, userId.Value);
                if (chat == null)
                {
                    _logger.LogWarning("GetMessages: Unauthorized chat access attempt. ChatId={ChatId}, UserId={UserId}, TraceId={TraceId}", 
                        chatId.Value, userId.Value, traceId);
                    return Unauthorized(new { error = "Chat not found or you don't have access to it", traceId });
                }

                // Get messages for this chat
                var messages = await _chatService.GetMessagesAsync(chatId.Value, userId.Value);

                // Return messages in a format suitable for frontend
                var messageList = messages.Select(m => new
                {
                    id = m.Id,
                    chatId = m.ChatId,
                    senderId = m.SenderId,
                    content = m.Content,
                    createdAt = m.CreatedAt
                }).ToList();

                return Ok(new { messages = messageList, traceId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetMessages: Unhandled exception. TraceId={TraceId}, ExceptionType={ExceptionType}, Message={Message}", 
                    traceId, ex.GetType().Name, ex.Message);
                return StatusCode(500, new { error = $"An unexpected server error occurred: {ex.Message}", traceId });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetQuiz(long? chatId)
        {
            var traceId = HttpContext.TraceIdentifier;
            
            try
            {
                if (!chatId.HasValue)
                {
                    return BadRequest(new { error = "chatId is required", traceId });
                }

                var userId = await ResolveUserIdAsync();
                if (!userId.HasValue)
                {
                    _logger.LogWarning("GetQuiz: User not authenticated. TraceId={TraceId}", traceId);
                    return Unauthorized(new { error = "User not authenticated", traceId });
                }

                // SECURITY: Verify chat belongs to user
                var chat = await _chatService.GetChatByIdAsync(chatId.Value, userId.Value);
                if (chat == null)
                {
                    _logger.LogWarning("GetQuiz: Unauthorized chat access attempt. ChatId={ChatId}, UserId={UserId}, TraceId={TraceId}", 
                        chatId.Value, userId.Value, traceId);
                    return Unauthorized(new { error = "Chat not found or you don't have access to it", traceId });
                }

                // Load quiz for this chat
                var quiz = await _dbContext.ChatQuizzes
                    .AsNoTracking()
                    .FirstOrDefaultAsync(q => q.ChatId == chatId.Value);

                if (quiz == null)
                {
                    return Ok(new { quiz = (object?)null, traceId });
                }

                // Parse quiz_json and return it
                try
                {
                    var quizData = quiz.QuizData;
                    if (quizData == null)
                    {
                        return Ok(new { quiz = (object?)null, traceId });
                    }

                    // Return quiz data in the expected format
                    return Ok(new 
                    { 
                        quiz = new
                        {
                            id = quiz.Id,
                            chat_id = quiz.ChatId,
                            quiz_json = JsonSerializer.Deserialize<object>(quiz.QuizJson),
                            created_at = quiz.CreatedAt
                        },
                        traceId 
                    });
                }
                catch (JsonException jsonEx)
                {
                    _logger.LogError(jsonEx, "GetQuiz: Failed to parse quiz JSON. QuizId={QuizId}, TraceId={TraceId}", quiz.Id, traceId);
                    return StatusCode(500, new { error = "Failed to parse quiz data", traceId });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetQuiz: Unhandled exception. TraceId={TraceId}, ExceptionType={ExceptionType}, Message={Message}", 
                    traceId, ex.GetType().Name, ex.Message);
                return StatusCode(500, new { error = $"An unexpected server error occurred: {ex.Message}", traceId });
            }
        }

        // POST: /StudyChat/SaveCustomizeAI
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> SaveCustomizeAI([FromBody] CustomizeAIRequest request)
        {
            var traceId = HttpContext.TraceIdentifier;
            
            try
            {
                var userId = await ResolveUserIdAsync();
                if (!userId.HasValue)
                {
                    _logger.LogWarning("SaveCustomizeAI: User not authenticated. TraceId={TraceId}", traceId);
                    return Unauthorized(new { error = "User not authenticated", traceId });
                }

                if (request?.Text == null)
                {
                    return BadRequest(new { error = "Text is required", traceId });
                }

                var text = request.Text.Trim();
                if (text.Length > 500)
                {
                    return BadRequest(new { error = "Text cannot exceed 500 characters", traceId });
                }

                // Check if customization already exists
                var existing = await _dbContext.Customizes
                    .FirstOrDefaultAsync(c => c.UserId == userId.Value);

                if (existing != null)
                {
                    // Update existing
                    existing.Text = text;
                    existing.UpdatedAt = DateTimeOffset.UtcNow;
                    _dbContext.Customizes.Update(existing);
                }
                else
                {
                    // Create new
                    var customize = new Models.Customize
                    {
                        UserId = userId.Value,
                        Text = text,
                        CreatedAt = DateTimeOffset.UtcNow,
                        UpdatedAt = DateTimeOffset.UtcNow
                    };
                    _dbContext.Customizes.Add(customize);
                }

                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("SaveCustomizeAI: Saved customization for user {UserId}. TraceId={TraceId}", userId.Value, traceId);

                return Ok(new { success = true, traceId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SaveCustomizeAI: Unhandled exception. TraceId={TraceId}, ExceptionType={ExceptionType}, Message={Message}", 
                    traceId, ex.GetType().Name, ex.Message);
                return StatusCode(500, new { error = $"An unexpected server error occurred: {ex.Message}", traceId });
            }
        }
    }

    // Request model for SendMessage endpoint
    public class SendMessageRequest
    {
        public string? Message { get; set; }
        public long? ChatId { get; set; }
        public string? Type { get; set; } = "normal"; // "normal" or "quiz"
    }

    public class CustomizeAIRequest
    {
        public string? Text { get; set; }
    }
}

