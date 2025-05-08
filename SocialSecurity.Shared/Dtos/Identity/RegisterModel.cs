using System.ComponentModel.DataAnnotations;

namespace SocialSecurity.Shared.Dtos.Identity
{
    public class RegisterModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
} 