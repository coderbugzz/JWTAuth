using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using JWTAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace  JWTAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class JWTAuthController : ControllerBase
    {
         private IConfiguration _config;    
    
        public JWTAuthController(IConfiguration config)    
        {    
            _config = config;    
        }    
        [AllowAnonymous]    
        [HttpPost("Login")]    
        public IActionResult Login([FromBody]LoginModel login)    
        {    
            // IActionResult response = Unauthorized();    

            var user = AuthenticateUser(login);    
    
            if (user != null)    
            {    
                var tokenString = GenerateJWT(user);    
               return Ok(new { token = tokenString });    
            }    else
            {
                return Unauthorized();
            }
    
            
        }    

        [HttpGet]    
        [Authorize]    
        public ActionResult<IEnumerable<string>> Get()    
        {    

            var currentUser = HttpContext.User;    
            DateTime TokenDate = new DateTime();    
            
            if (currentUser.HasClaim(c => c.Type == "Date"))    
            {    
                TokenDate = DateTime.Parse(currentUser.Claims.FirstOrDefault(c => c.Type == "Date").Value);    
                    
            }    
            
          return Ok("Custom Claims(date): " + TokenDate);
          
        }
    
        private string GenerateJWT(LoginModel userInfo)    
        {    
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtAuth:Key"]));    
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);    
    

        //claim is used to add identity to JWT token
        var claims = new[] {    
                new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username),    
                new Claim(JwtRegisteredClaimNames.Email, userInfo.EmailAddress),    
                new Claim("Date", DateTime.Now.ToString()),    
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())    
            };    
            

            var token = new JwtSecurityToken(_config["JwtAuth:Issuer"],    
              _config["JwtAuth:Issuer"],    
              claims,    //null original value
              expires: DateTime.Now.AddMinutes(120),    
              signingCredentials: credentials);    
    
            return new JwtSecurityTokenHandler().WriteToken(token);    
        }    
    
        private LoginModel AuthenticateUser(LoginModel login)    
        {    
            LoginModel user = null;    
    
            if (login.Username == "freecode")    
            {    
                user = new LoginModel { Username = "freecode", EmailAddress = "freecode@gmail.com" };    
            }    
            return user;    
        }
    }
}