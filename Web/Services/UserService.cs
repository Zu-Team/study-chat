using System.Linq;
using Microsoft.EntityFrameworkCore;
using Web.Data;
using Web.Models;

namespace Web.Services;

public class UserService
{
    private readonly ApplicationDbContext _context;

    public UserService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<User> UpsertGoogleUserAsync(string googleSub, string email, string? name)
    {
        var now = DateTimeOffset.UtcNow;
        User? user = null;

        // 1. Try to find by google_sub
        user = await _context.Users
            .FirstOrDefaultAsync(u => u.GoogleSub == googleSub);

        if (user != null)
        {
            // Update last login
            user.LastLoginAt = now;
            user.EmailVerified = true;
            await _context.SaveChangesAsync();
            return user;
        }

        // 2. Try to find by email
        user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user != null)
        {
            // Update existing user with Google info
            user.GoogleSub = googleSub;
            user.AuthProvider = "google";
            user.EmailVerified = true;
            user.LastLoginAt = now;
            if (string.IsNullOrEmpty(user.FullName) && !string.IsNullOrEmpty(name))
            {
                user.FullName = name;
            }
            await _context.SaveChangesAsync();
            return user;
        }

        // 3. Create new user
        user = new User
        {
            Id = Guid.NewGuid(),
            FullName = name,
            Email = email,
            GoogleSub = googleSub,
            AuthProvider = "google",
            EmailVerified = true,
            IsActive = true,
            CreatedAt = now,
            LastLoginAt = now
        };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return user;
        }
        catch (Exception ex)
        {
            // Log and rethrow to see the actual error
            throw new Exception($"Database error in UpsertGoogleUserAsync: {ex.Message}", ex);
        }
    }
        catch (Exception ex)
        {
            // Log and rethrow to see the actual error
            throw new Exception($"Database error in UpsertGoogleUserAsync: {ex.Message}", ex);
        }
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.IsActive);
    }
}

