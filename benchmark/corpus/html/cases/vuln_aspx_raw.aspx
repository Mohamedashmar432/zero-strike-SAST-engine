<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Demo.DefaultPage" %>
<!DOCTYPE html>
<html>
<body>
<form id="form1" runat="server">
    <p>Last search: <%= Request.QueryString["q"] %></p>
</form>
</body>
</html>
