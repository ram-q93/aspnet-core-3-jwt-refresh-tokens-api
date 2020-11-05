using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using WebApi.Helpers;
using WebApi.Models;
using WebApi.Services;

namespace WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly AppSettings _appSettings;

        public UsersController(IUserService userService, IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _appSettings = appSettings.Value;
        }


        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] AuthenticateRequest model)
        {
            //http://localhost:4000/users/authenticate
            var response = _userService.Authenticate(model, getIpAddress());
            if (response == null)
            {
                return BadRequest(new { message = "Username or password is incorrect" });
            }
            setRefreshTokenCookie(response.RefreshToken);
            return Ok(response);
        }


        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken()
        {
            //http://localhost:4000/users/refresh-token
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _userService.RefreshToken(refreshToken, getIpAddress());
            if (response == null)
            {
                return Unauthorized(new { message = "Invalid token" });
            }
            setRefreshTokenCookie(response.RefreshToken);
            return Ok(response);
        }


        [HttpPost("revoke-token")]
        public IActionResult RevokeToken([FromBody] RevokeTokenRequest model)
        {
            //To revoke a refresh token so it can no longer be used to generate JWT tokens
            // accept token from request body or cookie
            var token = model.RefreshToken ?? Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(token))
            {
                return BadRequest(new { message = "Refresh Token is required" });
            }
            var response = _userService.RevokeToken(token, getIpAddress());
            if (!response)
            {
                return NotFound(new { message = "Refresh Token not found" });
            }
            return Ok(new { message = "Refresh Token revoked" });
        }


        [HttpGet]
        public IActionResult GetAll() => Ok(_userService.GetAll());

        [HttpGet("{id}")]
        public IActionResult GetById(int id)
        {
            var user = _userService.GetById(id);
            if (user == null) return NotFound();
            return Ok(user);
        }

        [HttpGet("{id}/refresh-tokens")]
        public IActionResult GetRefreshTokens(int id)
        {
            //To get all refresh tokens for a user including active and revoked tokens, follow these steps:
            var user = _userService.GetById(id);
            if (user == null) return NotFound();
            return Ok(user.RefreshTokens);
        }


        // helper methods

        private void setRefreshTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.Now.AddMinutes(_appSettings.RefreshTokenExpiresInMinutes)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string getIpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
