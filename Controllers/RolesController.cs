using AuthAPI.Dtos;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace AuthAPI.Controllers
{
    [Authorize(Roles = "Admin, User")]
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;
        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser>
        userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if (string.IsNullOrEmpty(createRoleDto.RoleName))
            {
                return BadRequest("Role name is Required");
            }
            var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);
            if (roleExist)
            {
                return BadRequest("Role already exist");
            }
            var roleResult = await _roleManager.CreateAsync(new
            IdentityRole(createRoleDto.RoleName));
            if (roleResult.Succeeded)
            {
                return Ok(new { message = "Role Created successfully" });
            }
            return BadRequest("Role creation failed");
        }
        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
        {
            //list of users with total user count
            var roles = await _roleManager.Roles.Select(r => new RoleResponseDto
            {
                Id = r.Id,
                Name = r.Name,
                //TotalUsers = _userManager.GetUsersInRoleAsync(r.Name!).Result.Count
            }).ToListAsync();
            foreach (var role in roles)
            {
                role.TotalUsers = _userManager.GetUsersInRoleAsync(role.Name!).Result.Count;
            }
            return Ok(roles);
        }
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            //delete role by their id
            var role = await _roleManager.FindByIdAsync(id);
            if (role is null)
            {
                return NotFound("Role not found.");
            }
            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role deleted successfully." });
            }
            return BadRequest("Role deletion failed.");
        }
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await _userManager.FindByIdAsync(roleAssignDto.UserId);
            if (user is null)
            {
                return NotFound("User not found");
            }
            var role = await _roleManager.FindByIdAsync(roleAssignDto.RoleId);
            if (role is null)
            {
                return NotFound("Role not found.");
            }
            var result = await _userManager.AddToRoleAsync(user, role.Name!);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role assigned successfully" });
            }
            var error = result.Errors.FirstOrDefault();
            return BadRequest(error!.Description);
        }
    }
}