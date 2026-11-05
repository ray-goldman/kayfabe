class Operations : ExternalBase {
    private static string Pick(string unused, string selected) { return selected; }
    public void Run(string input) {
        info.Arguments = "/c " + Pick(unused: "ignored", selected: input);
        command.CommandText = "SELECT " + Pick(selected: input, unused: "ignored");
        new SqlCommand("SELECT " + Pick(unused: "ignored", selected: input), connection);
    }
}
