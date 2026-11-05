class Operations : ExternalBase {
    private static string Pick(string unused, string selected) { return selected; }
    public void Run(string input) {
        info.Arguments = "/c " + Pick(unused: "ignored", selected: "status");
        command.CommandText = "SELECT " + Pick(selected: "1", unused: "ignored");
        new SqlCommand("SELECT " + Pick(unused: "ignored", selected: "1"), connection);
    }
}
