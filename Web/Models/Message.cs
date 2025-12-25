using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Web.Models;

[Table("messages")]
public class Message
{
    [Key]
    [Column("id")]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required]
    [Column("chat_id")]
    public long ChatId { get; set; }

    [Column("sender_id")]
    public long? SenderId { get; set; }

    [Required]
    [Column("content")]
    public string Content { get; set; } = string.Empty;

    [Column("tool_tag")]
    [MaxLength(100)]
    public string? ToolTag { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Navigation properties
    [ForeignKey("ChatId")]
    public virtual Chat Chat { get; set; } = null!;

    [ForeignKey("SenderId")]
    public virtual User? Sender { get; set; }
}

