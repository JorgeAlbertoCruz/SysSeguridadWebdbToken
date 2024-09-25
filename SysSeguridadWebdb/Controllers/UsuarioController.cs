using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SysSeguridadWebdb.Auth;
using SysSeguridadWebdb.Models;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace SysSeguridadWebdb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UsuarioController : ControllerBase
    {
        private readonly BbContext _context;
        private static readonly string _key = "ESFE2024SecretKeyForTokenAuthentication";
        private readonly JwtAuthentication _jwtAuthentication = new JwtAuthentication(_key);

        public UsuarioController(BbContext context)
        {
          
            _context = context;
          
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult> Login(Usuario pUsuario)
        {
            var option = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            Usuario usuario_auth = await _context.Usuario.Where(x => x.Login == pUsuario.Login && x.Password == _jwtAuthentication.EncriptarMD5(pUsuario.Password)).FirstOrDefaultAsync();
            if (usuario_auth != null && usuario_auth.Id > 0 )
            {
                var token = _jwtAuthentication.Authenticate(usuario_auth);
                return Ok(token);
            }
            else
            {
                return Unauthorized();
            }
        }

        // GET: api/Usuario
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Usuario>>> GetUsuario()
        {
          if (_context.Usuario == null)
          {
              return NotFound();
          }
            return await _context.Usuario.ToListAsync();
        }

        // GET: api/Usuario/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Usuario>> GetUsuario(int id)
        {
          if (_context.Usuario == null)
          {
              return NotFound();
          }
            var usuario = await _context.Usuario.FindAsync(id);

            if (usuario == null)
            {
                return NotFound();
            }

            return usuario;
        }

        // PUT: api/Usuario/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutUsuario(int id, Usuario usuario)
        {
            if (id != usuario.Id)
            {
                return BadRequest();
            }

            // Encriptar la contraseña solo si no está vacía
            if (!string.IsNullOrEmpty(usuario.Password))
            {
                usuario.Password = _jwtAuthentication.EncriptarMD5(usuario.Password);
            }

            _context.Entry(usuario).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UsuarioExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }


        // POST: api/Usuario
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<Usuario>> PostUsuario(Usuario usuario)
        {
            if (_context.Usuario == null)
            {
                return Problem("Entity set 'BbContext.Usuario' is null.");
            }

            // Encriptar la contraseña antes de guardarla
            usuario.Password = _jwtAuthentication.EncriptarMD5(usuario.Password);

            _context.Usuario.Add(usuario);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetUsuario", new { id = usuario.Id }, usuario);
        }


        // DELETE: api/Usuario/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUsuario(int id)
        {
            if (_context.Usuario == null)
            {
                return NotFound();
            }
            var usuario = await _context.Usuario.FindAsync(id);
            if (usuario == null)
            {
                return NotFound();
            }

            _context.Usuario.Remove(usuario);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool UsuarioExists(int id)
        {
            return (_context.Usuario?.Any(e => e.Id == id)).GetValueOrDefault();
        }


    }
}
