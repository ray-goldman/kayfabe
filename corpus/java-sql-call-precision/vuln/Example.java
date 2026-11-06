class Example {
    String data = request.getParameter("name");
    void executeDynamic() {
        String data = request.getParameter("name");
        boolean result = sqlStatement.execute("SELECT name FROM users WHERE name='" + data + "'");
    }
    void queryDynamic() {
        String data = request.getParameter("name");
        jdbcTemplate.queryForObject("SELECT name FROM users WHERE name='" + data + "'", Long.class);
    }
}
