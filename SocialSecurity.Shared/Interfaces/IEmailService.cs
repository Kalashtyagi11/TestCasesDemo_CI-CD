namespace SocialSecurity.Shared.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
        Task SendVerificationCodeAsync(string email, string code);
        Task SendPasswordResetLinkAsync(string email, string resetLink);
    }
} 