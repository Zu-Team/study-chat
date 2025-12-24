using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Web.Models;

[Table("users")]
public class User
{
    [Key]
    [Column("id")]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Column("full_name")]
    [MaxLength(500)]
    public string? FullName { get; set; }

    [Required]
    [Column("email")]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Column("profile_image_path")]
    [MaxLength(1000)]
    public string? ProfileImagePath { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    [Column("password_hash")]
    public string? PasswordHash { get; set; }

    [Required]
    [Column("auth_provider")]
    [MaxLength(50)]
    public string AuthProvider { get; set; } = "local";

    [Column("google_sub")]
    [MaxLength(255)]
    public string? GoogleSub { get; set; }

    [Required]
    [Column("email_verified")]
    public bool EmailVerified { get; set; } = false;

    [Column("last_login_at")]
    public DateTimeOffset? LastLoginAt { get; set; }

    [Required]
    [Column("is_active")]
    public bool IsActive { get; set; } = true;

    // Navigation properties
    public virtual ICollection<Chat> Chats { get; set; } = new List<Chat>();
    public virtual ICollection<Message> Messages { get; set; } = new List<Message>();
    public virtual ICollection<Session> Sessions { get; set; } = new List<Session>();
}

