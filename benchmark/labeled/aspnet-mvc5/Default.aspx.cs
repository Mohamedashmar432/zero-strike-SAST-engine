using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Web.UI;

namespace LegacyShop
{
    public partial class DefaultPage : Page
    {
        protected void btnGo_Click(object sender, EventArgs e)
        {
            Response.Write("Hello " + txtName.Text);

            lblMsg.Text = Server.HtmlEncode(txtName.Text);

            var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["Shop"].ConnectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT Name FROM Products WHERE Name LIKE '%" + txtSearch.Text + "%'", conn);
            cmd.ExecuteReader();
        }
    }
}
