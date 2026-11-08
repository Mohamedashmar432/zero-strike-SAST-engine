<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="LegacyShop.DefaultPage" %>
<!DOCTYPE html>
<html>
<head runat="server"><title>Legacy Shop</title></head>
<body>
<form id="form1" runat="server">
    <asp:TextBox ID="txtName" runat="server" />
    <asp:TextBox ID="txtSearch" runat="server" />
    <asp:Button ID="btnGo" runat="server" Text="Go" OnClick="btnGo_Click" />
    <asp:Label ID="lblMsg" runat="server" />
    <p>Last search: <%= Request.QueryString["q"] %></p>
    <p>Encoded: <%: Request.QueryString["q"] %></p>
</form>
</body>
</html>
