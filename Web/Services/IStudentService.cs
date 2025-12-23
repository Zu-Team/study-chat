using Web.Models;

namespace Web.Services;

public interface IStudentService
{
    Task<IEnumerable<Student>> GetAllStudentsAsync();
}

