using Microsoft.EntityFrameworkCore;
using Web.Models;

namespace Web.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
    public DbSet<Chat> Chats { get; set; }
    public DbSet<Message> Messages { get; set; }
    public DbSet<Session> Sessions { get; set; }
    public DbSet<ChatSummary> ChatSummaries { get; set; }
    public DbSet<ChatQuiz> ChatQuizzes { get; set; }

    // Legacy - can be removed if not needed
    public DbSet<Student> Students { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(e => e.Email).IsUnique();
            entity.HasIndex(e => e.GoogleSub).IsUnique().HasFilter("\"google_sub\" IS NOT NULL");
        });

        // Chat configuration
        modelBuilder.Entity<Chat>(entity =>
        {
            entity.HasOne(c => c.User)
                .WithMany(u => u.Chats)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(c => c.Session)
                .WithMany(s => s.Chats)
                .HasForeignKey(c => c.SessionId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // Message configuration
        modelBuilder.Entity<Message>(entity =>
        {
            entity.HasOne(m => m.Chat)
                .WithMany(c => c.Messages)
                .HasForeignKey(m => m.ChatId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(m => m.Sender)
                .WithMany(u => u.Messages)
                .HasForeignKey(m => m.SenderId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(m => m.ChatId);
            entity.HasIndex(m => m.CreatedAt);
        });

        // Session configuration
        modelBuilder.Entity<Session>(entity =>
        {
            entity.HasOne(s => s.User)
                .WithMany(u => u.Sessions)
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // ChatSummary configuration
        modelBuilder.Entity<ChatSummary>(entity =>
        {
            entity.HasOne(cs => cs.Chat)
                .WithOne(c => c.ChatSummary)
                .HasForeignKey<ChatSummary>(cs => cs.ChatId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // ChatQuiz configuration
        modelBuilder.Entity<ChatQuiz>(entity =>
        {
            entity.HasOne(cq => cq.Chat)
                .WithOne(c => c.ChatQuiz)
                .HasForeignKey<ChatQuiz>(cq => cq.ChatId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}

