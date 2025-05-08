namespace SocialSecurity.Shared.Dtos.Identity
{
    public class RegisterDto
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? MobileNumber { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }
} 