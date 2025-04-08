using JwtAuthDotNet.Entities;
using JwtAuthDotNet.Models;
using JwtAuthDotNet.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {     
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null) return BadRequest("UserName is already exists.");

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<ResponseTokenDto>> Login(UserDto request)
        {
            var result = await authService.LoginAsync(request);
            if (result is null) return BadRequest("User name or password is incorrect");
                        
            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<ResponseTokenDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokenAsync(request);
            if (result == null || result.AccessToken == null || result.RefreshToken == null) return Unauthorized("Invalid refresh token.");
            return Ok(result);
        }


        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("You are authenticated.");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AuthenticatedEndpoint()
        {
            return Ok("you are admin and authenticated.");
        }
        
    }
}
