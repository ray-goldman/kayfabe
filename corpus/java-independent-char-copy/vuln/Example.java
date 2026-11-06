import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Example extends HttpServlet {
  private String choose(HttpServletRequest request, String input) {
    return input;
  }
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    String input = request.getParameter("value");
    String selected = choose(request, input);
    String alias = selected;
    response.getWriter().println(alias.toCharArray());
  }
}
