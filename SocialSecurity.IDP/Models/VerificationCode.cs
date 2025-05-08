using System;

namespace SocialSecurity.IDP.Models
{
    public class VerificationCode
    {
        public required string Email { get; set; }
        public required string Code { get; set; }
        public DateTime ExpirationTime { get; set; }
        public bool IsVerified { get; set; }
    }
} 