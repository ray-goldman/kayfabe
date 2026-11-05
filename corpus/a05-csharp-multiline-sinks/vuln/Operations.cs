using System.Data.SqlClient;
using System.Diagnostics;
public class Operations {
    public void Run(string input, SqlConnection connection) {
        var command = new SqlCommand("SELECT Id FROM Tasks WHERE Name = '" +
            input + "'", connection);
        Process.Start("cmd.exe", "/c echo " +
            input);
        var options = new ProcessStartInfo("cmd.exe");
        options.Arguments = "/c echo " +
            input;
        Process.Start(options);
        command.CommandText = "SELECT Id FROM Tasks WHERE Name = '" +
            input + "'";
    }
}
