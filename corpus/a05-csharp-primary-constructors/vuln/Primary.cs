using System.Diagnostics;
using System.Linq;
using Microsoft.Data.SqlClient;

class Primary(string input)
{
    void Run(SqlConnection connection)
    {
        { string input = "unrelated sibling"; }
        using var command = new SqlCommand("SELECT Name FROM Items WHERE Name = '" +
            input + "'", connection);
        Process.Start("cmd.exe", "/c echo " + input);
    }

    void Iterate(string[] inputs, SqlCommand command, ProcessStartInfo info)
    {
        foreach (string value in inputs)
        {
            command.CommandText = "SELECT Name FROM Items WHERE Name = '" + value + "'";
            info.Arguments = "/c echo " + value;
        }
        { string value = "unrelated sibling"; }
    }

    void Coalesce(SqlCommand command, ProcessStartInfo info)
    {
        string value = null;
        value ??= input;
        command.CommandText = "SELECT Name FROM Items WHERE Name = '" + value + "'";
        info.Arguments = "/c echo " + value;
    }

    void Query(string[] inputs)
    {
        { string value = "unrelated sibling"; }
        {
            var commands = from value in inputs
                           select new SqlCommand("SELECT Name FROM Items WHERE Name = '" + value + "'");
            commands.ToList();
        }
    }
}
