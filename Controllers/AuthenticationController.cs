using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using authserver.Models;
using authserver.Services;

namespace authserver.Controllers
{
    [ApiController]
    public class AuthenticationController : Controller
    {
        private readonly UserService _userService;

        public AuthenticationController(UserService userService)
        {
            _userService = userService;
        }

        [HttpPost("~/api/login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            Console.WriteLine(login.ToString());
            var user = _userService.GetUserByEmail(login.Username);

            if (user == null)
            {
                return Unauthorized();
            }

            // TODO: Password Validation

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, login.Username)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                // Set additional authentication properties if needed
            };

            await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));
            //if (Url.IsLocalUrl(login.ReturnUrl))
            //{
            //    return Redirect(login.ReturnUrl);
            //}

            return Ok(new { success = true });
        }

        [HttpGet("~/api/logout")]
        public IActionResult Logout()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Ok(new { success = true });
        }

        [HttpPost("~/api/register")]
        [AllowAnonymous]
        public IActionResult Register([FromBody] UserModel user)
        {
            try
            {
                if (_userService.CreateUser(user))
                {
                    return Ok(new { success = true });
                }
            } catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return BadRequest(ex.Message);
            }
            return BadRequest();
        }

        [HttpGet("~/api/test")]
        [Authorize]
        public IActionResult GetUser([FromQuery] string email)
        {
            try
            {
                UserModel user;
                if ((user = _userService.GetUserByEmail(email)) != null)
                {
                    return Ok(new { user });
                }
                else
                {
                    return Ok(new { user = false });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return BadRequest(ex.Message);
            }
        }
    }
}
