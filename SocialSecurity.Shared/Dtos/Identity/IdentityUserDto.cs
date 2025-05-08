namespace SocialSecurity.Shared.Dtos.Identity
{
    public class IdentityUserDto
    {
        public string Token { get; set; } = string.Empty;
        public ApplicationUserDto User { get; set; } = new();
    }

    public class ApplicationUserDto
    {
        public Guid Id { get; set; }
        public string? Email { get; set; }
        public string? UserName { get; set; }
        public string? MobileNumber { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }
} 