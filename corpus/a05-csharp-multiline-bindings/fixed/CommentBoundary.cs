using Microsoft.Data.SqlClient;
using System.Diagnostics;
class CommentBoundary {
    void Run(string input, SqlConnection connection) {
        const string value = "status";
        new SqlCommand("SELECT '" +
            value + "'", connection);
        Process.Start("cmd.exe", "/c echo " +
            value);
    }
}
