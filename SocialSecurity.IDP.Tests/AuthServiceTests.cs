using Moq;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using SocialSecurity.Application.Interfaces;
using SocialSecurity.Application.Services;
using SocialSecurity.Domain.Models;
using SocialSecurity.Shared.Dtos.Identity;
using Xunit;
using SocialSecurity.Shared.Interfaces;
using System.Reflection;

namespace SocialSecurity.IDP.Tests
{
    public class AuthServiceTests
    {
        private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
        private readonly Mock<SignInManager<ApplicationUser>> _mockSignInManager;
        private readonly Mock<IConfiguration> _mockConfiguration;
        private readonly Mock<IUnitOfWork> _mockUnitOfWork;
        private readonly Mock<IEmailService> _mockEmailService;
        private readonly AuthService _authService;
        private static readonly Dictionary<string, VerificationCode> _verificationCodes;

        static AuthServiceTests()
        {
            // Get the static _verificationCodes field from AuthService
            var field = typeof(AuthService).GetField("_verificationCodes", BindingFlags.NonPublic | BindingFlags.Static);
            _verificationCodes = (Dictionary<string, VerificationCode>)field.GetValue(null);
        }

        public AuthServiceTests()
        {
            // Setup UserManager mock
            var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
            _mockUserManager = new Mock<UserManager<ApplicationUser>>(
                userStoreMock.Object, null, null, null, null, null, null, null, null);

            // Setup SignInManager mock
            _mockSignInManager = new Mock<SignInManager<ApplicationUser>>(
                _mockUserManager.Object,
                Mock.Of<Microsoft.AspNetCore.Http.IHttpContextAccessor>(),
                Mock.Of<IUserClaimsPrincipalFactory<ApplicationUser>>(),
                null, null, null, null);

            // Setup Configuration mock
            _mockConfiguration = new Mock<IConfiguration>();
            _mockConfiguration.Setup(x => x["Jwt:Key"]).Returns("YourSecretKeyHere12345678901234567890");
            _mockConfiguration.Setup(x => x["Jwt:Issuer"]).Returns("YourIssuer");
            _mockConfiguration.Setup(x => x["Jwt:Audience"]).Returns("YourAudience");
            _mockConfiguration.Setup(x => x["Jwt:ExpireDays"]).Returns("7");

            // Setup UnitOfWork mock
            _mockUnitOfWork = new Mock<IUnitOfWork>();

            // Setup EmailService mock
            _mockEmailService = new Mock<IEmailService>();

            // Instantiate AuthService with mocks
            _authService = new AuthService(
                _mockUserManager.Object,
                _mockSignInManager.Object,
                _mockConfiguration.Object,
                _mockUnitOfWork.Object,
                _mockEmailService.Object
            );
        }

        [Fact]
        public async Task InitiateRegistration_WithNewEmail_SendsVerificationCode()
        {
            // Arrange
            var email = "test@example.com";
            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync((ApplicationUser)null);

            // Act
            var result = await _authService.InitiateRegistrationAsync(email);

            // Assert
            Assert.True(result);
            _mockEmailService.Verify(x => x.SendVerificationCodeAsync(email, It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task InitiateRegistration_WithExistingEmail_ThrowsException()
        {
            // Arrange
            var email = "existing@example.com";
            var existingUser = new ApplicationUser { Email = email };
            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(existingUser);

            // Act & Assert
            await Assert.ThrowsAsync<Exception>(() => _authService.InitiateRegistrationAsync(email));
        }

        [Fact]
        public async Task VerifyRegistrationCode_WithValidCode_ReturnsTrue()
        {
            // Arrange
            var email = "test@example.com";
            var code = "1234";
            
            // Store verification code directly in the static dictionary
            _verificationCodes[email] = new VerificationCode
            {
                Email = email,
                Code = code,
                ExpirationTime = DateTime.UtcNow.AddMinutes(10),
                IsVerified = false
            };

            // Act
            var result = await _authService.VerifyRegistrationCodeAsync(email, code);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task VerifyRegistrationCode_WithInvalidCode_ThrowsException()
        {
            // Arrange
            var email = "test@example.com";
            var code = "1234";
            
            // Store verification code directly in the static dictionary
            _verificationCodes[email] = new VerificationCode
            {
                Email = email,
                Code = code,
                ExpirationTime = DateTime.UtcNow.AddMinutes(10),
                IsVerified = false
            };

            // Act & Assert
            await Assert.ThrowsAsync<Exception>(() => _authService.VerifyRegistrationCodeAsync(email, "9999"));
        }

        [Fact]
        public async Task CompleteRegistration_WithVerifiedEmail_CreatesUser()
        {
            // Arrange
            var registerDto = new RegisterDto
            {
                Email = "test@example.com",
                Password = "Test@1234",
                FirstName = "Test",
                LastName = "User"
            };

            // Store verification code directly in the static dictionary
            _verificationCodes[registerDto.Email] = new VerificationCode
            {
                Email = registerDto.Email,
                Code = "1234",
                ExpirationTime = DateTime.UtcNow.AddMinutes(10),
                IsVerified = true
            };

            _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerDto.Password))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _authService.CompleteRegistrationAsync(registerDto);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(result.Token);
            Assert.Equal(registerDto.Email, result.User.Email);
        }

        [Fact]
        public async Task Login_WithValidCredentials_ReturnsUserAndToken()
        {
            // Arrange
            var loginDto = new LoginDto { Email = "test@example.com", Password = "Test@1234" };
            var userId = Guid.NewGuid().ToString();
            var user = new ApplicationUser { Id = userId, Email = "test@example.com", UserName = "testuser" };

            _mockUserManager.Setup(x => x.FindByEmailAsync(loginDto.Email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.PasswordSignInAsync(user, loginDto.Password, false, false))
                .ReturnsAsync(SignInResult.Success);

            // Act
            var result = await _authService.LoginAsync(loginDto);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(result.Token);
            Assert.Equal(user.Email, result.User.Email);
            Assert.Equal(user.UserName, result.User.UserName);
        }

        [Fact]
        public async Task ChangePassword_WithValidCredentials_ReturnsTrue()
        {
            // Arrange
            var email = "test@example.com";
            var currentPassword = "OldPass123";
            var newPassword = "NewPass123";
            var user = new ApplicationUser { Email = email };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockUserManager.Setup(x => x.ChangePasswordAsync(user, currentPassword, newPassword))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _authService.ChangePasswordAsync(email, currentPassword, newPassword);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task ForgotPassword_WithValidEmail_ReturnsTrue()
        {
            // Arrange
            var email = "test@example.com";
            var user = new ApplicationUser { Email = email };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user))
                .ReturnsAsync("reset-token");

            // Act
            var result = await _authService.ForgotPasswordAsync(email);

            // Assert
            Assert.True(result);
        }
    }
} 