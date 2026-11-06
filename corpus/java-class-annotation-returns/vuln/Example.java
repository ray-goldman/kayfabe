@sample.Metadata(label = "service", description = "{ } < > ( ) @Marker")
class Example {
  private String choose(Request request, Response response, String input) {
    String answer = input;
    return answer;
  }
  @Override
  protected void run(Request request, Response response) {
    String input = request.getParameter("name");
    String selected = choose(request, response, input);
    statement.executeQuery("SELECT name FROM users WHERE name='" + selected + "'");
  }
}
