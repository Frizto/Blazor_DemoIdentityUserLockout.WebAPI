using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoIdentityUserLockout.WebAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
{
    [HttpPost("register/{email}/{password}")]
    public async Task<IActionResult> Register(string email, string password)
    {
        var result = await userManager.CreateAsync(new IdentityUser 
        { 
            Email = email, 
            UserName = email,
            PasswordHash = password
        }, password);
        return Ok(result);
    }

    //Helper methods
    private async Task<IdentityUser?> GetUser(string email)
    {
        return await userManager.FindByEmailAsync(email);
    }

    private string GenerateToken(IdentityUser? identityUser)
    {
        var credential = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sEVy2SFvAJVp6fNm1IGM8qM8mnGcsRvH")),
            SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Email, identityUser?.Email),
        };

        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            issuer: null,
            audience: null,
            claims: claims,
            expires: null/*DateTime.Now.AddMinutes(30)*/,
            signingCredentials: credential
        ));

        return token;
    }

    [HttpPost("login/{email}/{password}")]
    public async Task<IActionResult> Login(string email, string password)
    {
        if (await GetUser(email) is null)
            return NotFound("User not found");

        // Check if user is locked out
        if (await userManager.IsLockedOutAsync(await GetUser(email)))
            return Unauthorized("User is locked out");

        // Check if password is correct
        if (!await userManager.CheckPasswordAsync(await GetUser(email), password))
        {
            // Increase failed login attempts in case its not
            var increaseCounter = await userManager.AccessFailedAsync(await GetUser(email));
            if (increaseCounter.Succeeded)
            {
                var failedAttempts = await userManager.GetAccessFailedCountAsync(await GetUser(email));
                return failedAttempts == 0 ?
                    Unauthorized("User is locked out") :
                    Unauthorized($"{3 - failedAttempts} - Attempts remaining.");
            }
            return NoContent();
        }

        // Reset failed login attempts in case password is correct
        var resetAttempt = userManager.ResetAccessFailedCountAsync(await GetUser(email));
        if (resetAttempt.Result.Succeeded)
            return Ok(new[] {"Login Success", GenerateToken(await GetUser(email))});
        else
            return NoContent();
    }
}
