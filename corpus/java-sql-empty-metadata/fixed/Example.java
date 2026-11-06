class Example {
    String data = request.getParameter("name");
    void queryConstant() {
        String data = "known";
        jdbcTemplate.queryForObject("SELECT name FROM users WHERE name='" + data + "'", new Object[]{}, String.class);
    }
    void executeConstant() {
        String data = "known";
        sqlStatement.execute("SELECT name FROM users WHERE name='" + data + "'", new java.lang.Object[] {}, String.class);
    }
}
