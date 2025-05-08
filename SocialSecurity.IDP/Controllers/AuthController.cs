using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SocialSecurity.Application.Interfaces;
using SocialSecurity.Shared.Dtos.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using SocialSecurity.Domain.Models;
using SocialSecurity.IDP.Models;
using SocialSecurity.Shared.Services;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SocialSecurity.IDP.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("initiate-registration")]
        public async Task<IActionResult> InitiateRegistration([FromBody] Shared.Dtos.Identity.RegisterModel model)
        {
            try
            {
                await _authService.InitiateRegistrationAsync(model.Email);
                return Ok(new { Status = "Success", Message = "Verification code sent to your email." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Status = "Error", Message = ex.Message });
            }
        }

        [HttpPost("verify-and-complete-registration")]
        public async Task<IActionResult> VerifyAndCompleteRegistration([FromBody] CompleteRegistrationModel model)
        {
            try
            {
                var registerDto = new RegisterDto
                {
                    Email = model.Email,
                    Password = model.Password,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    MobileNumber = model.MobileNumber
                };

                var result = await _authService.CompleteRegistrationAsync(registerDto);
                return Ok(new { Status = "Success", Message = "Registration completed successfully!", Data = result });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Status = "Error", Message = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            try
            {
                var result = await _authService.LoginAsync(loginDto);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        //[Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto changePasswordDto)
        {
            try
            {
                var result = await _authService.ChangePasswordAsync(
                    changePasswordDto.Email,
                    changePasswordDto.CurrentPassword,
                    changePasswordDto.NewPassword);
                return Ok(new { message = "Password changed successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
        {
            try
            {
                var result = await _authService.ForgotPasswordAsync(forgotPasswordDto.Email);
                return Ok(new { message = "Password reset link has been sent to your email" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            try
            {
                var result = await _authService.ResetPasswordAsync(
                    resetPasswordDto.ResetToken,
                    resetPasswordDto.NewPassword);
                return Ok(new { message = "Password has been reset successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }

    public class CompleteRegistrationModel
    {
        public string Email { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? MobileNumber { get; set; }
    }
} 