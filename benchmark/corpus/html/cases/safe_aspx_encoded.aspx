<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Demo.DefaultPage" %>
<!DOCTYPE html>
<html>
<body>
<form id="form1" runat="server">
    <%-- ZS-HTML-029 look-alike: <%: %> encodes, <%= %> over an encoder is fine. --%>
    <p>Encoded: <%: Request.QueryString["q"] %></p>
    <p>Also encoded: <%= HttpUtility.HtmlEncode(Request.QueryString["q"]) %></p>
</form>
</body>
</html>
