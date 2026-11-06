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
}
