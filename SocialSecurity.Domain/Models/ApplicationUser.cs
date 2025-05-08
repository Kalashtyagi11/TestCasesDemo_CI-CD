using Microsoft.AspNetCore.Identity;

namespace SocialSecurity.Domain.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? MobileNumber { get; set; }
        public string? OTP { get; set; }
        public DateTime? OTPExpiryDate { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
        public DateTime? LastModifiedDate { get; set; }
    }
} 