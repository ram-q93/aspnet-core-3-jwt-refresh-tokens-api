using Microsoft.EntityFrameworkCore;

namespace WebApi.DataAccess
{
    public class DataContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public DataContext(DbContextOptions<DataContext> options) : base(options) { }
    }
}