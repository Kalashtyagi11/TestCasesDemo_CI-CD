using System;

namespace SocialSecurity.Domain.Models
{
    public class VerificationCode
    {
        public string Email { get; set; }
        public string Code { get; set; }
        public DateTime ExpirationTime { get; set; }
        public bool IsVerified { get; set; }
    }
} 