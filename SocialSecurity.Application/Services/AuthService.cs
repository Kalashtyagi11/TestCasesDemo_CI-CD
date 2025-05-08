using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SocialSecurity.Application.Interfaces;
using SocialSecurity.Domain.Models;
using SocialSecurity.Shared.Interfaces;
using SocialSecurity.Shared.Dtos.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace SocialSecurity.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEmailService _emailService;
        private static readonly Dictionary<string, VerificationCode> _verificationCodes = new Dictionary<string, VerificationCode>();

        public AuthService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            IUnitOfWork unitOfWork,
            IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _unitOfWork = unitOfWork;
            _emailService = emailService;
        }

        public async Task<bool> InitiateRegistrationAsync(string email)
        {
            var userExists = await _userManager.FindByEmailAsync(email);
            if (userExists != null)
            {
                throw new Exception("User already exists!");
            }

            // Generate verification code
            var verificationCode = GenerateVerificationCode();
            var expirationTime = DateTime.UtcNow.AddMinutes(10);

            // Store verification code
            _verificationCodes[email] = new VerificationCode
            {
                Email = email,
                Code = verificationCode,
                ExpirationTime = expirationTime,
                IsVerified = false
            };

            // Send verification email
            await _emailService.SendVerificationCodeAsync(email, verificationCode);

            return true;
        }

        public async Task<bool> VerifyRegistrationCodeAsync(string email, string code)
        {
            if (!_verificationCodes.TryGetValue(email, out var storedCode))
            {
                throw new Exception("No verification code found for this email.");
            }

            if (DateTime.UtcNow > storedCode.ExpirationTime)
            {
                _verificationCodes.Remove(email);
                throw new Exception("Verification code has expired.");
            }

            if (storedCode.Code != code)
            {
                throw new Exception("Invalid verification code.");
            }

            // Mark as verified
            storedCode.IsVerified = true;
            _verificationCodes[email] = storedCode;

            return true;
        }

        public async Task<IdentityUserDto> CompleteRegistrationAsync(RegisterDto registerDto)
        {
            if (!_verificationCodes.TryGetValue(registerDto.Email, out var storedCode) || !storedCode.IsVerified)
            {
                throw new Exception("Email not verified.");
            }

            var user = new ApplicationUser
            {
                UserName = registerDto.Email,
                Email = registerDto.Email,
                MobileNumber = registerDto.MobileNumber,
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);
            if (!result.Succeeded)
            {
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            // Clear verification code
            _verificationCodes.Remove(registerDto.Email);

            var token = GenerateJwtToken(user);
            return new IdentityUserDto
            {
                Token = token,
                User = new ApplicationUserDto
                {
                    Id = Guid.Parse(user.Id),
                    Email = user.Email,
                    UserName = user.UserName,
                    MobileNumber = user.MobileNumber,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        public async Task<IdentityUserDto> LoginAsync(LoginDto loginDto)
        {
            ApplicationUser? user = null;

            if (!string.IsNullOrEmpty(loginDto.Username))
                user = await _userManager.FindByNameAsync(loginDto.Username);
            else if (!string.IsNullOrEmpty(loginDto.Email))
                user = await _userManager.FindByEmailAsync(loginDto.Email);
            else if (!string.IsNullOrEmpty(loginDto.MobileNumber))
                user = await _userManager.Users.SingleOrDefaultAsync(u => u.MobileNumber == loginDto.MobileNumber);

            if (user == null)
                throw new Exception("User not found");

            if (!string.IsNullOrEmpty(loginDto.Password))
            {
                var result = await _signInManager.PasswordSignInAsync(user, loginDto.Password, false, false);
                if (!result.Succeeded)
                    throw new Exception("Invalid password");
            }
            else if (!string.IsNullOrEmpty(loginDto.OTP))
            {
                if (loginDto.OTP != user.OTP || user.OTPExpiryDate < DateTime.UtcNow)
                    throw new Exception("Invalid or expired OTP");
            }
            else
            {
                throw new Exception("Either password or OTP is required");
            }

            //var token = GenerateJwtToken(user);
            return new IdentityUserDto
            {
                //Token = token,
                User = new ApplicationUserDto
                {
                    Id = Guid.Parse(user.Id),
                    Email = user.Email,
                    UserName = user.UserName,
                    MobileNumber = user.MobileNumber,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        public async Task<bool> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                throw new Exception("User not found");

            var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));

            return true;
        }

        public async Task<bool> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                throw new Exception("User not found");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            // TODO: Implement email sending logic
            return true;
        }

        public async Task<bool> ResetPasswordAsync(string resetToken, string newPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetToken.Split('|')[0]);
            if (user == null)
                throw new Exception("User not found");

            var result = await _userManager.ResetPasswordAsync(user, resetToken, newPassword);
            if (!result.Succeeded)
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));

            return true;
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? string.Empty));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddDays(Convert.ToDouble(_configuration["Jwt:ExpireDays"]));

            var token = new JwtSecurityToken(
                _configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateVerificationCode()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[4];
                rng.GetBytes(bytes);
                var code = BitConverter.ToUInt32(bytes, 0) % 10000;
                return code.ToString("D4");
            }
        }
    }
} 