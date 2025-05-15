using LiteDB;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

var app = builder.Build();

string GenerateApiKey() => $"sk_{Guid.NewGuid():N}";

var db = new LiteDatabase("otp.db");

var apiKeys = db.GetCollection<ApiKey>("apikeys");

var otps = db.GetCollection<OtpCode>("otps");

var hostname = "localhost:62226";

app.MapPost("/test", async () => {

});

// POST /api-key
app.MapPost("/api-key", (UpdateWebhookRequest updateWebhookRequest) =>
{
    var key = GenerateApiKey();

    var record = new ApiKey(key, DateTime.UtcNow, updateWebhookRequest.WebhookUrl);

    apiKeys.Insert(record);

    return Results.Ok(new { apiKey = key });
});

app.MapPost("/otp", async (HttpRequest request, CreateOtpRequest payload) => { 

    var apiKey = request.Headers["x-api-key"].ToString();

    if (string.IsNullOrWhiteSpace(apiKey) || apiKeys.FindOne(k => k.Key == apiKey) is null)
        return Results.Unauthorized();

    if (!string.IsNullOrWhiteSpace(payload.Email) && !IsValidEmail(payload.Email))
        return Results.BadRequest("Invalid email format.");

    if (!string.IsNullOrWhiteSpace(payload.RedirectAfterVerify) && !IsValidRedirectUrl(payload.RedirectAfterVerify))
        return Results.BadRequest("Invalid redirect URL. Must be a valid HTTPS URL.");


    var code = new Random().Next(100000, 999999).ToString();
    var id = Guid.NewGuid().ToString("N");
    var magicLink = $"https://{hostname}/otp/verify?id={id}&code={code}";

    var otp = new OtpCode(
        Id: id,
        ApiKey: apiKey!,
        Code: code,
        MagicLink: magicLink,
        CreatedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddMinutes(10),
        Used: false,
        RedirectAfterVerify: payload.RedirectAfterVerify,
        Email: payload.Email
    );

    otps.Insert(otp);

    return Results.Ok(new {
        id = otp.Id,
        code = otp.Code,
        magicLink = otp.MagicLink,
        expiresAt = otp.ExpiresAt,
        otp.Email,
        otp.RedirectAfterVerify
    });
});

app.MapGet("/otp/verify", (HttpRequest request, IHttpClientFactory httpClientFactory) => { 

    var key = request.Headers["x-api-key"].ToString();

    var code = request.Query["code"].ToString();

    var id = request.Query["id"].ToString();

    OtpCode? otp = null;

    if (!String.IsNullOrEmpty(id)) {

        otp = otps.FindOne(o => o.Code == code && o.Id == id);

    } else {

        otp = otps.FindOne(o => o.Code == code && o.ApiKey == key);
    }

    if (otp is null)
        return Results.NotFound(new { error = "OTP not found." });

    if (otp.Used)
        return Results.BadRequest(new { error = "OTP already used." });

    if (otp.ExpiresAt < DateTime.UtcNow)
        return Results.BadRequest(new { error = "OTP expired." });

    if (otp.Code != code)
        return Results.BadRequest(new { error = "Invalid code." });

    var updatedOtp = otp with { Used = true };

    otps.Update(updatedOtp);

    var apiKey = apiKeys.FindOne(k => k.Key == otp.ApiKey);

    if (apiKey?.WebhookUrl != null) {

        var httpClient = httpClientFactory.CreateClient();

        var payload = new {
            otpId = otp.Id,
            email = otp.Email,
            verifiedAt = DateTime.UtcNow,
            redirect = otp.RedirectAfterVerify
        };

        _ = Task.Run(async () => {
            try {
                var res = await httpClient.PostAsJsonAsync(apiKey.WebhookUrl, payload);
                res.EnsureSuccessStatusCode();
            } catch (Exception ex) {
                Console.WriteLine($"[webhook failed] {ex.Message}");
            }
        });
    }

    return string.IsNullOrEmpty(otp.RedirectAfterVerify)
      ? Results.Ok("OTP verified")
      : Results.Redirect(otp.RedirectAfterVerify);
});

app.Run();

static bool IsValidEmail(string? email) {
    if (string.IsNullOrWhiteSpace(email))
        return false;

    var regex = new System.Text.RegularExpressions.Regex(
        @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase
    );

    return regex.IsMatch(email);
}


static bool IsValidRedirectUrl(string? url) {
    if (string.IsNullOrWhiteSpace(url))
        return false;

    if (Uri.TryCreate(url, UriKind.Absolute, out var uri)) {
        return uri.Scheme == Uri.UriSchemeHttps; // enforce HTTPS only
    }

    return false;
}

public record UpdateWebhookRequest(string? WebhookUrl);
public record CreateOtpRequest(string? Email, string? RedirectAfterVerify);
public record ApiKey(string Key, DateTime CreatedAt, string? WebhookUrl);
public record OtpCode(
    string Id, 
    string ApiKey, 
    string Code, 
    string? MagicLink, 
    DateTimeOffset CreatedAt, 
    DateTimeOffset ExpiresAt, 
    bool Used,
    string? Email,
    string? RedirectAfterVerify);

