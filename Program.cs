using Microsoft.EntityFrameworkCore;
using SandboxRazorIdentity.Areas.Identity.Data;
using SandboxRazorIdentity.Data;

var builder = WebApplication.CreateBuilder(args);

//Tambahkan DbContext untuk Identity
builder.Services.AddDbContext<SandboxRazorIdentityContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("LOCAL")));

// Tambahkan layanan Identity
builder.Services.AddDefaultIdentity<SandboxRazorIdentityUser>(options =>
{
    // Opsi konfigurasi Identity (password, lockout, dsb.)
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<SandboxRazorIdentityContext>();

// Tambahkan Razor Pages
builder.Services.AddRazorPages();

var app = builder.Build();

// Middleware
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Gunakan autentikasi dan otorisasi
app.UseAuthentication();
app.UseAuthorization();

// Map Razor Pages
app.MapRazorPages();

app.Run();
