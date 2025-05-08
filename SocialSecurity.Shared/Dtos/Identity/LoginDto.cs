namespace SocialSecurity.Shared.Dtos.Identity
{
    public class LoginDto
    {
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? MobileNumber { get; set; }
        public string? Password { get; set; }
        public string? OTP { get; set; }
    }
} 