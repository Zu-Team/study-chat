using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Web.Models;

[Table("chat_summaries")]
public class ChatSummary
{
    [Key]
    [Column("id")]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [Column("chat_id")]
    public Guid ChatId { get; set; }

    [Required]
    [Column("summary_text")]
    public string SummaryText { get; set; } = string.Empty;

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Navigation properties
    [ForeignKey("ChatId")]
    public virtual Chat Chat { get; set; } = null!;
}

