using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using TinyCsvParser;
using TinyCsvParser.Mapping;

var builder = WebApplication.CreateBuilder(args);

var corsPolicy = "AllowSpecificOrigin";
builder.Services.AddCors(options =>
{
    options.AddPolicy(
        corsPolicy,
        builder =>
        {
            builder
                .WithOrigins("http://localhost:3000", "http://localhost:3005")
                .AllowAnyMethod()
                .AllowCredentials()
                .AllowAnyHeader();
        }
    );
});

var SigningSecret = Environment.GetEnvironmentVariable("SigningSecret");
if (SigningSecret == null)
{
    throw new Exception("JWT key not found in environment variables.");
}

var IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningSecret));

builder
    .Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = GetValidationParameters();
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
app.UseCors(corsPolicy);
app.UseAuthentication();
app.UseAuthorization();

app.MapGet(
    "/api/download-epub/{bookName}",
    async (HttpContext context) =>
    {
        if(context.Request.RouteValues.TryGetValue("bookName", out var bookNameWrapper))
        {
            var bookName = bookNameWrapper.ToString();

            // Set the path to the EPUB file
            var epubFilePath = Path.Combine(
                app.Environment.ContentRootPath,
                "Data",
                bookName,
                bookName + "_modified.epub"
            );
            // Check if file exists
            if (!File.Exists(epubFilePath))
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("File not found");
                return;
            }
            // Read the file into a stream
            var fileStream = new FileStream(
                epubFilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read
            );
            // Set the content type for the response
            context.Response.ContentType = "application/epub+zip";
            // Set the file download name
            context.Response.Headers.Add(
                "Content-Disposition",
                "attachment; filename=Animal_Farm_v2.epub"
            );
            // Send the stream to the response
            await fileStream.CopyToAsync(context.Response.Body);
        }
    }
);

CsvParserOptions csvParserOptions = new CsvParserOptions(true, ',');
CsvParser<Character> csvCharacterParser = new CsvParser<Character>(
    csvParserOptions,
    new CsvCharacterMapping()
);
CsvParser<Sentence> csvSentenceParser = new CsvParser<Sentence>(
    csvParserOptions,
    new SentenceMapping()
);

app.MapGet(
    "/api/sentences/{bookName}",
    async (HttpContext context) =>
    {
        var token = context.Request.Cookies["token"];
        var validToken = ValidateToken(token);

        if (validToken &&
            context.Request.RouteValues.TryGetValue("bookName", out var bookNameWrapper)
        )
        {
            var bookName = bookNameWrapper.ToString();
            var csvFilePath = Path.Combine("Data", bookName, bookName + "_sentences.csv");
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
        }
        else
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        }
    }
);

app.MapGet(
    "/api/progress-info/{bookName}/{character}/{currentSid}",
    async context =>
    {
        var token = context.Request.Cookies["token"];
        var validToken = ValidateToken(token);

        if (validToken)
        {
            var routeValues = context.Request.RouteValues;

            if (
                routeValues.TryGetValue("bookName", out var bookNameWrapper)
                && routeValues.TryGetValue("character", out var characterWrapper)
                && routeValues.TryGetValue("currentSid", out var currentSidWrapper)
            )
            {
                var bookName = bookNameWrapper.ToString();
                var character = characterWrapper.ToString();
                int.TryParse(currentSidWrapper.ToString(), out var currentSid);

                var csvCharacterResults = csvCharacterParser
                    .ReadFromFile(
                        $"Data/{bookName}/merged_summaries.csv",
                        Encoding.ASCII
                    )
                    .ToList();

                var csvSentencesResults = csvSentenceParser
                    .ReadFromFile($"Data/{bookName}/{bookName}_sentences.csv", Encoding.ASCII)
                    .ToList();

                var allCharacterSummaries = csvCharacterResults.Where(x =>
                    x.IsValid && x.Result.Name.Equals(character)
                );

                // await context.Response.WriteAsJsonAsync(csvCharacterResults);

                var totalCharacterSummariesResult = allCharacterSummaries.Count(x => x.IsValid);

                var characterResult = allCharacterSummaries.Select(x => x.Result).FirstOrDefault();

                var unlockedCharacterSummariesResult = allCharacterSummaries
                    .Where(x => x.IsValid && x.Result.EndSid < currentSid)
                    .Count();

                var totalSidResult = csvSentencesResults.Count(x => x.IsValid);;

                await context.Response.WriteAsJsonAsync(
                    new
                    {
                        SidOfFirstCharacterSummary = characterResult.EndSid,
                        TotalSid = totalSidResult,
                        unlockedCharacterSummaries = unlockedCharacterSummariesResult,
                        TotalCharacterSummaries = totalCharacterSummariesResult,
                    }
                );

            }
        }
    }
);

app.MapGet(
    "/api/{bookName}/{character}/{sid}",
    async context =>
    {
        Console.WriteLine("is this working?");
        var token = context.Request.Cookies["token"];
        var validToken = ValidateToken(token);

        if (validToken)
        {
            CsvCharacterMapping csvMapper = new CsvCharacterMapping();
            CsvParser<Character> csvCharacterParser = new CsvParser<Character>(
                csvParserOptions,
                csvMapper
            );

            var routeValues = context.Request.RouteValues;

            // var result = new List<CsvMappingResult<Character>>();

            if (
                routeValues.TryGetValue("bookName", out var bookNameWrapper)
                && routeValues.TryGetValue("character", out var characterWrapper)
                && routeValues.TryGetValue("sid", out var sidWrapper)
            )
            {
                var bookName = bookNameWrapper.ToString();
                var character = characterWrapper.ToString();
                int.TryParse(sidWrapper.ToString(), out var sid);

                var csvResults = csvCharacterParser
                    .ReadFromFile(
                        $"Data/{bookName}/merged_summaries.csv",
                        Encoding.ASCII
                    )
                    .ToList();

                Character result = csvResults
                    .Where(x =>
                        x.IsValid && x.Result.Name.Equals(character) && x.Result.EndSid < sid
                    )
                    .Select(x => x.Result)
                    .OrderByDescending(x => x.EndSid)
                    .FirstOrDefault();

                await context.Response.WriteAsJsonAsync(result);
            }
        }
    }
);

app.MapPost(
        "/api/authenticate",
        async (User inputUser, HttpContext context) =>
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
                    Subject = new ClaimsIdentity(
                        new Claim[] { new Claim(ClaimTypes.Name, username) }
                    ),
                    Issuer = "localhost",
                    Audience = "localhost",
                    Expires = DateTime.UtcNow.AddHours(4),
                    SigningCredentials = new SigningCredentials(
                        IssuerSigningKey,
                        SecurityAlgorithms.HmacSha256Signature
                    )
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                var cookieOptions = new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddMinutes(5),
                    IsEssential = true,
                    HttpOnly = false,
                    Secure = false,
                    Domain = "localhost"
                };

                context.Response.Cookies.Append("token", tokenString, cookieOptions);
                context.Response.StatusCode = StatusCodes.Status200OK;
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            }
        }
    )
    .WithName("AuthenticateUser");

bool ValidateToken(string token)
{
    try
    {
        if (token.IsNullOrEmpty())
        {
            throw new NullReferenceException("Token is null");
        }
    }
    catch (NullReferenceException e)
    {
        Console.WriteLine(e);
        return false;
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = GetValidationParameters();

    SecurityToken validatedToken;

    try
    {
        Thread.CurrentPrincipal = tokenHandler.ValidateToken(
            token,
            validationParameters,
            out validatedToken
        );
    }
    catch (Exception e)
    {
        Console.WriteLine(e);
        return false;
    }

    return true;
}

TokenValidationParameters GetValidationParameters()
{
    return new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "localhost",
        IssuerSigningKey = IssuerSigningKey
    };
}

app.Run();
