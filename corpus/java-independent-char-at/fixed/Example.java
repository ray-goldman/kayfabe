import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
import java.sql.SQLException;

public class Example {
  private static String choose(HttpServletRequest request, String input) {
    final String alphabet = "ABC";
    char chosen = alphabet.charAt(1);
    String answer;
    switch (chosen) {
      case 66: answer = "fixed"; break;
      default: answer = input;
    }
    return answer;
  }

  public void run(HttpServletRequest request, Statement statement) throws SQLException {
    String input = request.getParameter("name");
    String selected = choose(request, input);
    statement.executeQuery("SELECT name FROM users WHERE name='" + selected + "'");
  }
}
