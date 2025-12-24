using System.Linq;
using Microsoft.EntityFrameworkCore;
using Web.Data;
using Web.Models;

namespace Web.Services;

public class ChatService
{
    private readonly ApplicationDbContext _context;

    public ChatService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<List<Chat>> GetChatsForUserAsync(Guid userId)
    {
        return await _context.Chats
            .Where(c => c.UserId == userId)
            .OrderByDescending(c => c.CreatedAt)
            .ToListAsync();
    }

    public async Task<Chat> CreateNewChatAsync(Guid userId)
    {
        var chat = new Chat
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Name = "New Chat",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _context.Chats.Add(chat);
        await _context.SaveChangesAsync();

        return chat;
    }

    public async Task<List<Message>> GetMessagesAsync(Guid chatId)
    {
        return await _context.Messages
            .Where(m => m.ChatId == chatId)
            .OrderBy(m => m.CreatedAt)
            .Include(m => m.Sender)
            .ToListAsync();
    }

    public async Task<Chat?> GetChatByIdAsync(Guid chatId, Guid userId)
    {
        return await _context.Chats
            .FirstOrDefaultAsync(c => c.Id == chatId && c.UserId == userId);
    }
}

