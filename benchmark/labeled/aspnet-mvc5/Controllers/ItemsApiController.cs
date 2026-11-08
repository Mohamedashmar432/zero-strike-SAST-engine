using System.Configuration;
using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace LegacyShop.Controllers
{
    [RoutePrefix("api/items")]
    public class ItemsApiController : ApiController
    {
        [HttpGet]
        [Route("search")]
        public IHttpActionResult Search([FromUri] string q)
        {
            var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["Shop"].ConnectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT Id, Name FROM Items WHERE Name LIKE '%" + q + "%'", conn);
            return Ok(cmd.ExecuteReader());
        }

        [HttpGet]
        [Route("by-sku")]
        public IHttpActionResult BySku([FromUri] string sku)
        {
            var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["Shop"].ConnectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT Id, Name FROM Items WHERE Sku = @sku", conn);
            cmd.Parameters.Add(new SqlParameter("@sku", sku));
            return Ok(cmd.ExecuteReader());
        }

        [HttpGet]
        [Route("image")]
        public HttpResponseMessage Image([FromUri] string name)
        {
            var bytes = File.ReadAllBytes(System.Web.Hosting.HostingEnvironment.MapPath("~/images/") + name);
            var response = Request.CreateResponse(HttpStatusCode.OK);
            response.Content = new ByteArrayContent(bytes);
            return response;
        }

        [HttpPost]
        [Route("webhook")]
        public IHttpActionResult Webhook([FromBody] string callbackUrl)
        {
            var req = (HttpWebRequest)WebRequest.Create(callbackUrl);
            return Ok(req.GetResponse().ContentLength);
        }
    }
}
