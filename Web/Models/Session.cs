using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Web.Models;

[Table("sessions")]
public class Session
{
    [Key]
    [Column("id")]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required]
    [Column("session_id")]
    [MaxLength(64)]
    public string SessionId { get; set; } = string.Empty; // GUID string for cookie-based session tracking

    [Column("user_id")]
    public long? UserId { get; set; } // Nullable - null before login, set to user ID after login

    [Column("title")]
    [MaxLength(500)]
    public string? Title { get; set; } // Optional - can be null for anonymous sessions

    [Column("ip_address")]
    [MaxLength(45)] // IPv6 max length
    public string? IpAddress { get; set; }

    [Column("user_agent")]
    [MaxLength(500)]
    public string? UserAgent { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    [Column("last_accessed_at")]
    public DateTimeOffset LastAccessedAt { get; set; } = DateTimeOffset.UtcNow;

    [Column("ended_at")]
    public DateTimeOffset? EndedAt { get; set; }

    // Navigation properties
    [ForeignKey("UserId")]
    public virtual User? User { get; set; }

    public virtual ICollection<Chat> Chats { get; set; } = new List<Chat>();
}

