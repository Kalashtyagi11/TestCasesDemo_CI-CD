using SocialSecurity.Shared.Dtos.Identity;

namespace SocialSecurity.Application.Interfaces
{
    public interface IAuthService
    {
        Task<IdentityUserDto> LoginAsync(LoginDto loginDto);
        Task<bool> ChangePasswordAsync(string email, string currentPassword, string newPassword);
        Task<bool> ForgotPasswordAsync(string email);
        Task<bool> ResetPasswordAsync(string resetToken, string newPassword);
        
        // Registration verification methods
        Task<bool> InitiateRegistrationAsync(string email);
        Task<bool> VerifyRegistrationCodeAsync(string email, string code);
        Task<IdentityUserDto> CompleteRegistrationAsync(RegisterDto registerDto);
    }
} 