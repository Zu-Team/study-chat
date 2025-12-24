using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Npgsql;
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

    public async Task<User> CreateLocalUserAsync(string email, string password, string? fullName)
    {
        if (string.IsNullOrWhiteSpace(email)) throw new ArgumentException("Email is required.", nameof(email));
        if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password is required.", nameof(password));

        var normalizedEmail = email.Trim();
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            FullName = string.IsNullOrWhiteSpace(fullName) ? null : fullName.Trim(),
            Email = normalizedEmail,
            AuthProvider = "local",
            EmailVerified = false,
            IsActive = true,
            CreatedAt = now,
            LastLoginAt = now
        };

        // Hash the password using ASP.NET Core's built-in password hasher (PBKDF2-based).
        var hasher = new PasswordHasher<User>();
        user.PasswordHash = hasher.HashPassword(user, password);

        try
        {
            // Avoid a pre-check SELECT: some deployments enforce restrictive SELECT/RLS policies.
            // Instead, rely on the unique index on email and translate unique-violation into a friendly message.
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return user;
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx)
        {
            // 23505 = unique_violation
            if (string.Equals(pgEx.SqlState, PostgresErrorCodes.UniqueViolation, StringComparison.Ordinal))
            {
                // Best-effort mapping: constraint names vary across environments.
                if ((pgEx.ConstraintName?.Contains("email", StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (pgEx.Detail?.Contains("email", StringComparison.OrdinalIgnoreCase) ?? false))
                {
                    throw new InvalidOperationException("A user with this email already exists.", ex);
                }
            }

            throw;
        }
    }

    public async Task<User> UpsertGoogleUserAsync(string googleSub, string email, string? name)
    {
        var now = DateTimeOffset.UtcNow;
        User? user = null;

        try
        {
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

    public async Task<bool> CreateGoogleUserIfNotExistsAsync(string googleSub, string email, string? name)
    {
        if (string.IsNullOrWhiteSpace(googleSub)) throw new ArgumentException("googleSub is required.", nameof(googleSub));
        if (string.IsNullOrWhiteSpace(email)) throw new ArgumentException("email is required.", nameof(email));

        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            FullName = string.IsNullOrWhiteSpace(name) ? null : name.Trim(),
            Email = email.Trim(),
            GoogleSub = googleSub.Trim(),
            AuthProvider = "google",
            EmailVerified = true,
            IsActive = true,
            CreatedAt = now,
            LastLoginAt = now
        };

        try
        {
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return true;
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx)
        {
            // 23505 = unique_violation (email/google_sub already exists)
            if (string.Equals(pgEx.SqlState, PostgresErrorCodes.UniqueViolation, StringComparison.Ordinal))
            {
                return false;
            }

            throw;
        }
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.IsActive);
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email && u.IsActive);
    }

    public async Task UpdateLastLoginAsync(User user)
    {
        if (user == null) throw new ArgumentNullException(nameof(user));
        user.LastLoginAt = DateTimeOffset.UtcNow;
        await _context.SaveChangesAsync();
    }
}

