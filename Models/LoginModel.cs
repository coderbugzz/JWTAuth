using System;

namespace JWTAuth.Models
{
     public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string EmailAddress { get; set; }
        public DateTime Date { get; set; } = DateTime.Now;
    }
}