using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;

namespace TicketDesk.Pages;

public class SearchModel : PageModel
{
    private readonly SqliteConnection _db;

    public SearchModel(SqliteConnection db) => _db = db;

    public string Query { get; set; } = "";
    public List<string> Titles { get; set; } = new();
    public string? Attachment { get; set; }

    public void OnGet(string? q, string? file)
    {
        Query = q ?? "";
        if (file != null)
        {
            Attachment = System.IO.File.ReadAllText(Path.Combine("wwwroot", "notes", Request.Query["file"]!));
        }
    }

    public IActionResult OnPost()
    {
        var term = Request.Form["term"];
        var cmd = _db.CreateCommand();
        cmd.CommandText = "SELECT Title FROM Tickets WHERE Title LIKE '%" + term + "%'";
        using var r = cmd.ExecuteReader();
        while (r.Read()) Titles.Add(r.GetString(0));
        return Page();
    }
}
