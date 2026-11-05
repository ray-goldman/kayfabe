using Microsoft.EntityFrameworkCore;
namespace Demo.Data {
    public class CatalogDb : DbContext {
        public CatalogDb(DbContextOptions<CatalogDb> options) : base(options) {}
        public DbSet<Listing> Listings { get; set; }
    }
    public class Listing { public int Id { get; set; } public string Name { get; set; } }
}
