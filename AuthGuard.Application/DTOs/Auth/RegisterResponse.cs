﻿namespace AuthGuard.Application.DTOs.Auth
{
    public class RegisterResponse
    {        
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? Role { get; set; }
    }
}
