using TinyCsvParser;
using TinyCsvParser.Mapping;
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
    var epubFilePath = Path.Combine(app.Environment.ContentRootPath, "Data", "animal-farm_modified.epub");
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

CsvParserOptions csvParserOptions = new CsvParserOptions(true, ',');
CsvParser<Character> csvCharacterParser = new CsvParser<Character>(csvParserOptions, new CsvCharacterMapping());
CsvParser<Sentence> csvSentenceParser = new CsvParser<Sentence>(csvParserOptions, new SentenceMapping());

app.MapGet("/sentences", async (HttpContext context) =>
{
    var csvFilePath = Path.Combine("Data", "animal-farm", "sentences_df_animal_farm.csv");
    var result = csvSentenceParser.ReadFromFile(csvFilePath, Encoding.UTF8);
    var sentences = result.ToList().Where(r => r.IsValid).Select(r => r.Result).ToList();

    if (sentences.Count > 0)
    {
        await context.Response.WriteAsJsonAsync(sentences);
    }
    else
    {
        await context.Response.WriteAsJsonAsync(new { Error = "Empty_List" });
    }
});


app.MapGet("/progress-info/{bookName}/{character}/{currentSid}", async context => 
{
    var routeValues = context.Request.RouteValues;
    
    if(routeValues.TryGetValue("bookName", out var bookNameWrapper) &&
        routeValues.TryGetValue("character", out var characterWrapper) &&
        routeValues.TryGetValue("currentSid", out var currentSidWrapper))
    {
        var bookName = bookNameWrapper.ToString();
        var character = characterWrapper.ToString();
        int.TryParse(currentSidWrapper.ToString(), out var currentSid);

        var csvCharacterResults = csvCharacterParser
            .ReadFromFile($"Data/{bookName}/merged_summaries_animal_farm.csv", Encoding.ASCII)
            .ToList();

        var csvSentencesResults = csvSentenceParser
            .ReadFromFile($"Data/{bookName}/sentences_df_animal_farm.csv", Encoding.ASCII)
            .ToList();

        var allCharacterSummaries = csvCharacterResults  
            .Where(x => x.IsValid && x.Result.Name.Equals(character));
        
        var totalCharacterSummariesResult = allCharacterSummaries.Count(x => x.IsValid);

        var characterResult = allCharacterSummaries
            .Select(x => x.Result)
            .FirstOrDefault();

        var unlockedCharacterSummariesResult = allCharacterSummaries
            .Where(x => x.IsValid && x.Result.EndSid < currentSid)
            .Count();
        
        var totalSidResult = csvSentencesResults.Count(x => x.IsValid);
        
        await context.Response.WriteAsJsonAsync(new { 
            SidOfFirstCharacterSummary = characterResult.EndSid, 
            TotalSid = totalSidResult, 
            unlockedCharacterSummaries = unlockedCharacterSummariesResult,
            TotalCharacterSummaries = totalCharacterSummariesResult,
        });
    }
});

app.MapGet("/{bookName}/{character}/{sid}", async context =>
{
    CsvCharacterMapping csvMapper = new CsvCharacterMapping();
    CsvParser<Character> csvCharacterParser = new CsvParser<Character>(csvParserOptions, csvMapper);

    var routeValues = context.Request.RouteValues;

    // var result = new List<CsvMappingResult<Character>>();
    
    if(routeValues.TryGetValue("bookName", out var bookNameWrapper) &&
        routeValues.TryGetValue("character", out var characterWrapper) &&
        routeValues.TryGetValue("sid", out var sidWrapper))
    {
        var bookName = bookNameWrapper.ToString();
        var character = characterWrapper.ToString();
        int.TryParse(sidWrapper.ToString(), out var sid);

        var csvResults = csvCharacterParser
            .ReadFromFile($"Data/{bookName}/merged_summaries_animal_farm.csv", Encoding.ASCII)
            .ToList();

        Character result = csvResults  
            .Where(x => x.IsValid && x.Result.Name.Equals(character) && x.Result.EndSid < sid)
            .Select(x => x.Result)
            .OrderByDescending(x => x.EndSid)
            .FirstOrDefault();
        
        await context.Response.WriteAsJsonAsync(result);
    }

});

app.MapPost("/authenticate", async (User inputUser, HttpContext context) =>
{
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
