class Example {
    String data = request.getParameter("name");
    void executeConstant() {
        String data = "known";
        boolean result = sqlStatement.execute("SELECT name FROM users WHERE name='" + data + "'");
    }
    void queryConstant() {
        String data = "known";
        jdbcTemplate.queryForObject("SELECT name FROM users WHERE name='" + data + "'", Long.class);
    }
    String returnedConstant() {
        String data = "known";
        return jdbcTemplate.queryForObject("SELECT name FROM users WHERE name='" + data + "'");
    }
    void wrappedConstant() {
        String data = "known";
        consume(jdbcTemplate.queryForObject("SELECT name FROM users WHERE name='" + data + "'"));
    }
}
