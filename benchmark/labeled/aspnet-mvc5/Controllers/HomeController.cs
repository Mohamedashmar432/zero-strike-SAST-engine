using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using System.Xml;

namespace LegacyShop.Controllers
{
    public class HomeController : Controller
    {
        private readonly ShopContext _db = new ShopContext();

        public ActionResult Product()
        {
            var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["Shop"].ConnectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT Name, Price FROM Products WHERE Id = " + Request.QueryString["id"], conn);
            var reader = cmd.ExecuteReader();
            return View(reader);
        }

        public ActionResult ProductSafe()
        {
            var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["Shop"].ConnectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT Name, Price FROM Products WHERE Id = @id", conn);
            cmd.Parameters.AddWithValue("@id", Request.QueryString["id"]);
            return View(cmd.ExecuteReader());
        }

        public ActionResult Customers(string name)
        {
            var rows = _db.Database.SqlQuery<Customer>("SELECT * FROM Customers WHERE Name = '" + name + "'").ToList();
            return View(rows);
        }

        public ActionResult CustomersSafe(string name)
        {
            var rows = _db.Database.SqlQuery<Customer>("SELECT * FROM Customers WHERE Name = @p0", name).ToList();
            return View(rows);
        }

        public ActionResult Manual(string f)
        {
            var text = System.IO.File.ReadAllText(Server.MapPath("~/docs/" + Request.QueryString["f"]));
            return Content(text);
        }

        public ActionResult ManualSafe(string f)
        {
            var docs = Server.MapPath("~/docs/");
            var full = Path.GetFullPath(Path.Combine(docs, Path.GetFileName(f)));
            if (!full.StartsWith(docs, StringComparison.OrdinalIgnoreCase)) return new HttpStatusCodeResult(400);
            return Content(System.IO.File.ReadAllText(full));
        }

        public ActionResult Leave()
        {
            return Redirect(Request.QueryString["returnUrl"]);
        }

        public ActionResult LeaveSafe(string returnUrl)
        {
            if (!Url.IsLocalUrl(returnUrl)) return RedirectToAction("Index");
            return Redirect(returnUrl);
        }

        [HttpPost]
        public ActionResult Feedback()
        {
            return Content("<p>Thanks, " + Request.Form["name"] + "</p>");
        }

        [HttpPost]
        public ActionResult FeedbackSafe()
        {
            return Content("<p>Thanks, " + Server.HtmlEncode(Request.Form["name"]) + "</p>");
        }

        [HttpPost]
        public ActionResult Diagnose()
        {
            Process.Start("cmd.exe", "/c dir " + Request.Form["dir"]);
            return new EmptyResult();
        }

        public ActionResult Cleanup()
        {
            return Content(ShellHelper.Run("cmd.exe", "/c del /q C:\\temp\\cache\\*.tmp"));
        }

        [HttpPost]
        public ActionResult Restore()
        {
            var obj = new BinaryFormatter().Deserialize(Request.InputStream);
            return Content(obj.ToString());
        }

        [HttpPost]
        public ActionResult RestoreTyped(string json)
        {
            var obj = new JavaScriptSerializer(new SimpleTypeResolver()).DeserializeObject(json);
            return Json(obj);
        }

        [HttpPost]
        public ActionResult RestoreSafe(string json)
        {
            var obj = new JavaScriptSerializer().Deserialize<Dictionary<string, string>>(json);
            return Json(obj);
        }

        public string HashPassword(string password)
        {
            var md5 = new MD5CryptoServiceProvider();
            return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        public string HashPasswordSafe(string password, byte[] salt)
        {
            var kdf = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(kdf.GetBytes(32));
        }

        public byte[] EncryptCard(byte[] card)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                return des.CreateEncryptor().TransformFinalBlock(card, 0, card.Length);
            }
        }

        public byte[] EncryptCardSafe(byte[] card)
        {
            using (var aes = Aes.Create())
            {
                return aes.CreateEncryptor().TransformFinalBlock(card, 0, card.Length);
            }
        }

        [HttpPost]
        public ActionResult ImportCatalog()
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
            var reader = XmlReader.Create(Request.InputStream, settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return Content(doc.OuterXml);
        }

        [HttpPost]
        public ActionResult ImportCatalogSafe()
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            var reader = XmlReader.Create(Request.InputStream, settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return Content(doc.OuterXml);
        }

        public ActionResult Preview()
        {
            var html = new WebClient().DownloadString(Request.QueryString["url"]);
            return Content(html);
        }

        public ActionResult Exchange(string currency)
        {
            var json = new WebClient().DownloadString("https://api.example.com/rates/" + Uri.EscapeDataString(currency));
            return Content(json, "application/json");
        }
    }

    public static class ShellHelper
    {
        // Only called with literal command lines from HomeController.Cleanup.
        public static string Run(string file, string args)
        {
            var p = Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, RedirectStandardOutput = true });
            return p.StandardOutput.ReadToEnd();
        }
    }
}
