using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Web.Models;

[Table("chats")]
public class Chat
{
    [Key]
    [Column("id")]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required]
    [Column("user_id")]
    public long UserId { get; set; }

    [Column("session_id")]
    public long? SessionId { get; set; }

    [Column("name")]
    [MaxLength(500)]
    public string? Name { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Navigation properties
    [ForeignKey("UserId")]
    public virtual User User { get; set; } = null!;

    [ForeignKey("SessionId")]
    public virtual Session? Session { get; set; }

    public virtual ICollection<Message> Messages { get; set; } = new List<Message>();
    public virtual ChatSummary? ChatSummary { get; set; }
    public virtual ChatQuiz? ChatQuiz { get; set; }
}

