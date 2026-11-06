using Microsoft.Data.SqlClient;
using System.Diagnostics;
class Commands {
    void Run(string input, SqlConnection connection) {
        string value = null;
        (value) ??= input;
        new SqlCommand("SELECT " +
            value, connection);
        Process.Start("cmd.exe", "/c " +
            value);
    }
}
