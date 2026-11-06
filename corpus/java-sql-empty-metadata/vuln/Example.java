class Example {
    String data = request.getParameter("name");
    void queryDynamic() {
        String data = request.getParameter("name");
        jdbcTemplate.queryForObject("SELECT name FROM users WHERE name='" + data + "'", new Object[]{}, String.class);
    }
    void executeDynamic() {
        String data = request.getParameter("name");
        sqlStatement.execute("SELECT name FROM users WHERE name='" + data + "'", new java.lang.Object[] {}, String.class);
    }
}
