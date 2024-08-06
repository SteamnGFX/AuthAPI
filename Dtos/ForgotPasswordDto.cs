﻿using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos
{
	public class ForgotPasswordDto
	{
       [Required]
       [EmailAddress]
       public string Email { get; set; } = string.Empty;

    }
}

