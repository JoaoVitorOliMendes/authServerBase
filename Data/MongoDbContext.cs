using authserver.Models;
using Microsoft.EntityFrameworkCore;

namespace authserver.Data
{
    public class MongoDbContext : DbContext
    {
        public DbSet<UserModel> UserModel { get; init; }
        public MongoDbContext(DbContextOptions options)
            : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //base.OnModelCreating(modelBuilder);
            //modelBuilder.Entity<UserModel>().ToCollection("users");
        }
    }
}
