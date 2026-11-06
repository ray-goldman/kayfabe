class Example {
  private String choose(Request request, Response response, String input) {
    String answer = input;
    return answer;
  }
  void run(Request request, Response response) {
    String input = request.getParameter("name");
    String selected = choose(request, response, input);
    statement.executeQuery("SELECT name FROM users WHERE name='" + selected + "'");
  }
}
