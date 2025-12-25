using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Web.Models;

/// <summary>
/// Represents an anonymous visitor session that can be created before user authentication.
/// When a user authenticates, this session can be linked to their User account.
/// </summary>
[Table("visitor_sessions")]
public class VisitorSession
{
    [Key]
    [Column("id")]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required]
    [Column("session_id")]
    [MaxLength(64)]
    public string SessionId { get; set; } = string.Empty; // GUID stored as string

    [Column("user_id")]
    public long? UserId { get; set; } // Nullable - can be linked when user authenticates

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

    // Navigation property
    [ForeignKey("UserId")]
    public virtual User? User { get; set; }
}

