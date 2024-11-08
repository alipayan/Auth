using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("bearer")
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("OrbitalSecure#@887235887235887236")),
            ValidateIssuer = false,
            ValidateAudience = false
        };
        options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
        {
            //we can read the token from access-token instead of authorization header
            OnMessageReceived = receivedMessage =>
            {
                var accessToken = receivedMessage.HttpContext.Request.Query["access_token"];
                if (string.IsNullOrEmpty(accessToken))
                {
                    receivedMessage.Fail("invalid token in your queyr string");
                }
                receivedMessage.Token = accessToken;

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthentication("github-default")
    .AddOAuth("github", options =>
    {
        options.ClientId = "test";
        options.ClientSecret = "test";
        options.CallbackPath = "/";
        options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        options.TokenEndpoint = "https://github.com/login/oauth/access_token";
        options.SignInScheme = "github-default";

        options.Events.OnCreatingTicket = async context =>
        {
            var accessToken = context.AccessToken;
            var httpReuqest = new HttpRequestMessage(HttpMethod.Get, options.UserInformationEndpoint);
            httpReuqest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await context.Backchannel.SendAsync(httpReuqest);
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("");
            }

            //insert data of user to data base
            var rawBody = await response.Content.ReadAsStringAsync(context.HttpContext.RequestAborted);

            using var payload = JsonDocument.Parse(rawBody);

        };

    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.MapGet("/github", () =>
{
    return TypedResults.Challenge(new Microsoft.AspNetCore.Authentication.AuthenticationProperties
    {
        RedirectUri = "/callback",//place where user should return after authorize by other applications

    }, authenticationSchemes: ["github"]);
});

app.MapGet("/userinfo", (HttpContext context) =>
{
    context.User.FindFirst("sub");
});

app.MapGet("/get-jwt-token", () =>
{

    var secretKey = "OrbitalSecure#@887235887235887236";
    var secretKeyAtBytes = Encoding.UTF8.GetBytes(secretKey);
    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub","theEnd"),
            new Claim("mobile","09131815446")
        }),
        Expires = DateTime.UtcNow.AddDays(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyAtBytes),
        SecurityAlgorithms.HmacSha256)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    var a = tokenHandler.WriteToken(token);

    return a;
});


app.Run();
