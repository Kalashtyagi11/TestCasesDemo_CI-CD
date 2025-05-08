using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using SocialSecurity.Shared.Interfaces;

namespace SocialSecurity.Shared.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var smtpSettings = _configuration.GetSection("SmtpSettings");
            var host = smtpSettings["Host"] ?? throw new InvalidOperationException("SMTP Host is not configured");
            var port = smtpSettings["Port"] ?? throw new InvalidOperationException("SMTP Port is not configured");
            var userName = smtpSettings["UserName"] ?? throw new InvalidOperationException("SMTP Username is not configured");
            var password = smtpSettings["Password"] ?? throw new InvalidOperationException("SMTP Password is not configured");
            var enableSsl = smtpSettings["EnableSSL"] ?? "false";

            using (var client = new SmtpClient(host, int.Parse(port)))
            {
                client.Credentials = new NetworkCredential(userName, password);
                client.EnableSsl = bool.Parse(enableSsl);

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(userName),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(toEmail);

                await client.SendMailAsync(mailMessage);
            }
        }

        public async Task SendVerificationCodeAsync(string email, string code)
        {
            var subject = "Email Verification Code";
            var body = $@"
                <div style='font-family: Arial, sans-serif; text-align: center;'>
                    <h2>Email Verification</h2>
                    <p>Your verification code is:</p>
                    <h3 style='background: #007bff; color: white; padding: 10px 20px; display: inline-block;'>{code}</h3>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>";

            await SendEmailAsync(email, subject, body);
        }

        public async Task SendPasswordResetLinkAsync(string email, string resetLink)
        {
            var subject = "Password Reset Request";
            var body = $@"
                <div style='font-family: Arial, sans-serif; text-align: center;'>
                    <h2>Password Reset</h2>
                    <p>Click the link below to reset your password:</p>
                    <a href='{resetLink}' style='background: #007bff; color: white; padding: 10px 20px; text-decoration: none; display: inline-block;'>Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>";

            await SendEmailAsync(email, subject, body);
        }
    }
} 