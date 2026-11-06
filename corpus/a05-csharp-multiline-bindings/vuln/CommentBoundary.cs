using Microsoft.Data.SqlClient;
using System.Diagnostics;
class CommentBoundary {
    void Run(string input, SqlConnection connection) {
        string value = "fixed";
        // C# NEL terminates this comment: value = input;
        new SqlCommand("SELECT " +
            value, connection);
        Process.Start("cmd.exe", "/c " +
            value);
    }
}
