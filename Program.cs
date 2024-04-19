using TinyCsvParser;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>{
    options.AddPolicy("AllowAll",
    builder =>
    {
        builder
        .WithOrigins("http://localhost:3000", "http://localhost:3005")
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

var SigningSecret = Environment.GetEnvironmentVariable("SigningSecret");
if (SigningSecret == null)
{
    throw new Exception("JWT key not found in environment variables.");
}

var IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningSecret));


builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)

    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "Issuer",
            ValidAudience = "Audience",
            IssuerSigningKey = IssuerSigningKey
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/download-epub", async (HttpContext http) =>
{
    // Set the path to the EPUB file
    var epubFilePath = Path.Combine(app.Environment.ContentRootPath, "Data", "Animal_Farm_v2.epub");
    // Check if file exists
    if (!File.Exists(epubFilePath))
    {
        http.Response.StatusCode = 404;
        await http.Response.WriteAsync("File not found");
        return;
    }
    // Read the file into a stream
    var fileStream = new FileStream(epubFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
    // Set the content type for the response
    http.Response.ContentType = "application/epub+zip";
    // Set the file download name
    http.Response.Headers.Add("Content-Disposition", "attachment; filename=Animal_Farm_v2.epub");
    // Send the stream to the response
    await fileStream.CopyToAsync(http.Response.Body);
});

app.MapPost("/authenticate", async (User inputUser, HttpContext context) =>
{
    var csvParserOptions = new CsvParserOptions(true, ',');
    var csvMapper = new CsvParser<User>(csvParserOptions, new UserMapping());
    var csvFilePath = Path.Combine("Data", "User.csv");
    var result = csvMapper.ReadFromFile(csvFilePath, System.Text.Encoding.UTF8);
    var users = result.ToList().Where(r => r.IsValid).Select(r => r.Result).ToList();

    var username = inputUser.Username;
    var password = inputUser.Password;

    var user = users.FirstOrDefault(u => u.Username == username && u.Password == password);

    if (user != null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.Name, username)
            }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(IssuerSigningKey, SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        await context.Response.WriteAsJsonAsync(new { Token = tokenString });
    }
    else
    {
        await context.Response.WriteAsJsonAsync(new { Error = "Invalid_Credentials" });
    }
})
.WithName("AuthenticateUser");

app.Run();
