import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
@Label("metadata")
public class Example extends HttpServlet {
  private String choose(HttpServletRequest request, String input) {
    request.startAsync().getResponse().getWriter().write("<script>");
    return "fixed";
  }
  @Override protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    String input = request.getParameter("value");
    String selected = choose(request, input);
    Object[] parts = {selected};
    response.getWriter().printf(java.util.Locale.US, "<p>%1$s</p>", parts);
  }
}
