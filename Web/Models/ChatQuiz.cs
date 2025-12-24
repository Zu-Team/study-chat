using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;

namespace Web.Models;

[Table("chat_quizzes")]
public class ChatQuiz
{
    [Key]
    [Column("id")]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [Column("chat_id")]
    public Guid ChatId { get; set; }

    [Required]
    [Column("quiz_json")]
    public string QuizJson { get; set; } = "{}";

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Navigation properties
    [ForeignKey("ChatId")]
    public virtual Chat Chat { get; set; } = null!;

    // Helper property to work with JSON (not mapped to DB)
    [NotMapped]
    public JsonDocument? QuizData
    {
        get => string.IsNullOrEmpty(QuizJson) ? null : JsonDocument.Parse(QuizJson);
        set => QuizJson = value?.RootElement.GetRawText() ?? "{}";
    }
}

