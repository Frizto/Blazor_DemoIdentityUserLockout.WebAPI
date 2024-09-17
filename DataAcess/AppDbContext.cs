using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DemoIdentityUserLockout.WebAPI.DataAcess;

public class AppDbContext(DbContextOptions options) : IdentityDbContext<IdentityUser>(options)
{

}
