namespace SocialSecurity.Shared.Dtos.Identity
{
    public class ResetPasswordDto
    {
        public string ResetToken { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
} 