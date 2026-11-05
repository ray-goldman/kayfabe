using System.Data.SqlClient;
using System.Diagnostics;
public class Operations {
    public void Run(SqlConnection connection) {
        const string name = "scheduled";
        var command = new SqlCommand("SELECT Id FROM Tasks WHERE Name = '" +
            name + "'", connection);
        Process.Start("cmd.exe", "/c echo " +
            "scheduled");
        var options = new ProcessStartInfo("cmd.exe");
        options.Arguments = "/c echo " +
            name;
        Process.Start(options);
        command.CommandText = "SELECT Id FROM Tasks WHERE Name = '" +
            name + "'";
        db.ExecuteSqlRaw("SELECT " + "1", new
            SqlCommand("SELECT '" + name + "'", connection).ExecuteReader());
    }
}
