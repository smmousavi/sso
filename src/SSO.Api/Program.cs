using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using sso.api.Configuration;
using sso.api.Services;
using SSO.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

// Configure Settings
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<RedisSettings>(builder.Configuration.GetSection("RedisSettings"));

// Configure DbContext
builder.Services.AddDbContext<SsoDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()!;
var redisSettings = builder.Configuration.GetSection("RedisSettings").Get<RedisSettings>()!;

// Add Redis distributed cache
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = redisSettings.ConnectionString;
    options.InstanceName = redisSettings.InstanceName;
});

// Add Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
        ClockSkew = TimeSpan.Zero
    };

    // Add token validation event to check revocation
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var sessionService = context.HttpContext.RequestServices.GetRequiredService<ISessionService>();
            var token = context.Request.Headers.Authorization.ToString().Replace("Bearer ", "");

            var isRevoked = await sessionService.IsTokenRevokedAsync(token);
            if (isRevoked)
            {
                context.Fail("Token has been revoked");
            }
        }
    };
});

builder.Services.AddAuthorization();

// Register Services
builder.Services.AddSingleton<IUserService, UserService>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IApplicationService, ApplicationService>();
builder.Services.AddSingleton<ISessionService, RedisSessionService>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SSO API",
        Version = "v1",
        Description = "Single Sign-On API with JWT Authentication and Multi-Application Support"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token"
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

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "SSO API v1"));
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
