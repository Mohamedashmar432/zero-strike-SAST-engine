public class CorsFilter {
    public void filter(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
    }
}
