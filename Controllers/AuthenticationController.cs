using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using authserver.Models;
using authserver.Services;
using authserver.Util;
using System.Text;
using DnsClient;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Collections.Immutable;

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
            var user = _userService.GetUserByEmail(login.Username);

            if (user == null)
            {
                return Unauthorized("Incorrect Credentials");
            }

            string storedHashedPassword = user.Password;
            string storedSalt = user.Salt;
            byte[] storedSaltBytes = Convert.FromBase64String(storedSalt);
            Console.WriteLine(storedSaltBytes);
            string enteredPassword = login.Password;

            byte[] enteredPasswordBytes = Encoding.UTF8.GetBytes(enteredPassword);

            byte[] saltedPassword = new byte[enteredPasswordBytes.Length + storedSaltBytes.Length];
            Buffer.BlockCopy(enteredPasswordBytes, 0, saltedPassword, 0, enteredPasswordBytes.Length);
            Buffer.BlockCopy(storedSaltBytes, 0, saltedPassword, enteredPasswordBytes.Length, storedSaltBytes.Length);

            string enteredPasswordHash = HashingUtils.HashPassword(enteredPassword, storedSaltBytes);

            if (enteredPasswordHash == storedHashedPassword)
            {
                var claims = new List<Claim>
                {
                    new Claim(Claims.Name, login.Username),
                    new Claim(Claims.Subject, user.Email),
                    new Claim(Claims.Email, user.Email),
                    new Claim(Claims.Role, String.Join(" ", new List<string> { "user", "admin" }.ToImmutableArray()))
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {

                };

                await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));
                return Ok(new { success = true });
            }
            else
            {
                return Unauthorized("Incorrect Credentials");
            }

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
            var userDb = _userService.GetUserByEmail(user.Email);

            if (userDb != null)
            {
                return Unauthorized("User already exists");
            }

            byte[] saltBytes = HashingUtils.GenerateSalt();
            // Hash the password with the salt
            string hashedPassword = HashingUtils.HashPassword(user.Password, saltBytes);
            string base64Salt = Convert.ToBase64String(saltBytes);

            //string retrievedSaltBytes = Convert.FromBase64String(base64Salt);

            user.Password = hashedPassword;
            user.Salt = base64Salt;
            Console.WriteLine(base64Salt);
            user.CreationDate = DateTime.Now;
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
