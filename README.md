# CatTree
A bash command to tree and recursively cat an entire directory. Extremely useful for working with AI.

```
cattree -h
Usage: cattree [-e extensions] [-d depth] [-a]
  -e, --extensions   Comma-separated list of file extensions to include (e.g., cs,json)
  -d, --depth        Depth level for the tree output and file search (e.g., 2)
  -a, --all          Include hidden directories and files (default is to exclude .vscode, .vs, bin, obj)
  -h, --help         Display this help message
```

```
❯ cattree -e "cs"

CatTreeing /Users/henrygetz/RiderProjects/WisarNet-JWT-Demo/WisarNetJwtDemo...

==================== ./Models/User.cs ====================

namespace WisarNetJwtDemo.Models
{
    public class User
    {
        // This property represents the unique identifier for the user in the database.
        public int Id { get; set; }

        // This property is typically used as a unique identifier for login purposes.
        public string Username { get; set; }

        // This property stores the user's password, which should be securely hashed before storage.
        public string Password { get; set; }

        // This stores the user's email address, used for communication or password recovery.
        public string Email { get; set; }

        // This list holds the roles assigned to the user, used for authorization.
        // It is initialized as a new list of strings, meaning it starts empty but ready to be added to.
        public List<string> Roles { get; set; } = new List<string>();
    }
}

==================== ./Models/Login.cs ====================

using System.ComponentModel.DataAnnotations;

namespace WisarNetJwtDemo.Models
{
    public class Login
    {
        // This property represents the username input from a user during the login process.
        // Usernames are essential for identifying the user in the system.
        // The Required attribute makes sure that the username field is not empty.
        // The StringLength attribute can be used to specify the maximum length of the username.
        [Required(ErrorMessage = "Username is required.")]
        [StringLength(100, ErrorMessage = "Username must be less than 100 characters.")]
        public string Username { get; set; }

        // This property is used to store the password input from a user during the login process.
        // Passwords need secure handling to prevent unauthorized access.
        // The Required attribute ensures the password field is not left empty.
        // The StringLength attribute can specify minimum and maximum password lengths, enhancing security.
        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be between 6 and 100 characters.")]
        public string Password { get; set; }
    }
}

==================== ./Models/UserStore.cs ====================

namespace WisarNetJwtDemo.Models
{
    public class UserStore
    {
        // Declare a public static list of User objects named 'Users'.
        // Being static, this list is shared across all instances of the UserStore class and accessible without creating an instance of the class.
        // This list is initialized with predefined user data.
        public static List<User> Users = new List<User>
        {
            new User { Id=1, Username = "admin", Password = "password", Email="admin@Example.com", Roles = new List<string> { "Admin", "User" } },
            new User { Id=2, Username = "user", Password = "password", Email="user@Example.com", Roles = new List<string> { "User" } },
            new User { Id=3, Username = "test", Password = "password", Email="test@Example.com", Roles = new List<string> { "Admin" } }
        };
    }
}

==================== ./Controllers/ResourceController.cs ====================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WisarNetJwtDemo.Models;

namespace WisarNetJwtDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ResourceController : ControllerBase
    {
        // Static list to simulate database of resources.
        private static List<User> _users = new List<User>
        {
            new User { Id = 1, Username = "admin", Email = "admin@example.com" },
            new User { Id = 2, Username = "user", Email = "user@example.com" },
            new User { Id = 3, Username = "test", Email = "test@example.com" }
        };

        // GET method to retrieve all users.
        [HttpGet]
        [Authorize]  // To secure the endpoints with JWT authentication
        public ActionResult<List<User>> GetAllUsers()
        {
            return _users;
        }

        // GET method with a parameter to retrieve a specific user by their ID.
        [HttpGet("{id}")]
        [Authorize]
        public ActionResult<User> GetUser(int id)
        {
            var user = _users.FirstOrDefault(u => u.Id == id);
            if (user == null)
                return NotFound();
            return user;
        }

        // POST method to create a new user.
        [HttpPost]
        [Authorize]
        public ActionResult<User> CreateUser([FromBody] User user)
        {
            _users.Add(user);
            return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
        }

        // PUT method to update an existing user.
        [HttpPut("{id}")]
        [Authorize]
        public ActionResult<User> UpdateUser(int id, [FromBody] User user)
        {
            var index = _users.FindIndex(u => u.Id == id);
            if (index == -1)
                return NotFound();

            _users[index] = user;
            return NoContent();
        }

        // DELETE method to remove a user by ID.
        [HttpDelete("{id}")]
        [Authorize]
        public IActionResult DeleteUser(int id)
        {
            var index = _users.FindIndex(u => u.Id == id);
            if (index == -1)
                return NotFound();

            _users.RemoveAt(index);
            return NoContent();
        }
    }
}


==================== ./Controllers/UsersController.cs ====================

using WisarNetJwtDemo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // Private field to hold the configuration settings injected through the constructor.
        private readonly IConfiguration _configuration;

        // Constructor that accepts IConfiguration and initializes the _configuration field.
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Action method responding to POST requests on "api/Users/Login".
        // Expects a Login model in the request body.
        [HttpPost("Login")]
        public IActionResult Login([FromBody] Login request)
        {
            // Checks if the provided model (request) is valid based on data annotations in the Login model.
            if (ModelState.IsValid)
            {
                // Searches for a user in a predefined user store that matches both username and password.
                var user = UserStore.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == request.Password);

                // Checks if the user object is null, which means no matching user was found.
                if (user == null)
                {
                    // Returns a 401 Unauthorized response with a custom message.
                    return Unauthorized("Invalid user credentials.");
                }

                // Calls a method to generate a JWT token for the authenticated user.
                var token = IssueToken(user);

                // Returns a 200 OK response, encapsulating the JWT token in an anonymous object.
                return Ok(new { Token = token });
            }

            // If the model state is not valid, returns a 400 Bad Request response with a custom message.
            return BadRequest("Invalid Request Body");
        }

        // Private method to generate a JWT token using the user's data.
        private string IssueToken(User user)
        {
            // Creates a new symmetric security key from the JWT key specified in the app configuration.
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            // Sets up the signing credentials using the above security key and specifying the HMAC SHA256 algorithm.
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Defines a set of claims to be included in the token.
            var claims = new List<Claim>
            {
                // Custom claim using the user's ID.
                new Claim("Myapp_User_Id", user.Id.ToString()),
                // Standard claim for user identifier, using username.
                new Claim(ClaimTypes.NameIdentifier, user.Username),
                // Standard claim for user's email.
                new Claim(ClaimTypes.Email, user.Email),
                // Standard JWT claim for subject, using user ID.
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString())
            };

            // Adds a role claim for each role associated with the user.
            user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

            // Creates a new JWT token with specified parameters including issuer, audience, claims, expiration time, and signing credentials.
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1), // Token expiration set to 1 hour from the current time.
                signingCredentials: credentials);

            // Serializes the JWT token to a string and returns it.
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

==================== ./Program.cs ====================

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models; // Make sure to include this namespace for OpenApi* classes
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = null; // Keep JSON properties as is
    });

// Configure JWT authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "WisarNetJwtDemo", Version = "v1" });

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your valid token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();


==================== Cat Tree ====================

 /\_/\
( o.o )
 > ^ <
   .
   ├── Controllers
   │   ├── ResourceController.cs
   │   └── UsersController.cs
   ├── Models
   │   ├── Login.cs
   │   ├── User.cs
   │   └── UserStore.cs
   └── Program.cs

   3 directories, 6 files



  ~/RiderProjects/WisarNet-JWT-Demo/WisarNetJwtDemo on   master +1 !1                                                                                           base at  09:27:53 PM
❯
```
