using System.Diagnostics;
using System.Linq;
using Microsoft.Data.SqlClient;

class Primary(string input)
{
    void Run(SqlConnection connection)
    {
        { string input = "unrelated sibling"; }
        const string value = "scheduled";
        using var command = new SqlCommand("SELECT Name FROM Items WHERE Name = '" +
            value + "'", connection);
        Process.Start("cmd.exe", "/c echo " + value);
    }

    void Iterate(string[] inputs, SqlCommand command, ProcessStartInfo info)
    {
        foreach (string value in inputs)
        {
            command.CommandText = "SELECT Name FROM Items WHERE Name = @name";
            command.Parameters.AddWithValue("@name", value);
            info.ArgumentList.Add(value);
        }
        { string value = "unrelated sibling"; }
    }

    void Coalesce(SqlCommand command, ProcessStartInfo info)
    {
        string value = null;
        ((value)) ??= input;
        command.CommandText = "SELECT Name FROM Items WHERE Name = @name";
        command.Parameters.AddWithValue("@name", value);
        info.ArgumentList.Add(value);
    }

    void Alias(SqlCommand command, ProcessStartInfo info)
    {
        string value = "fixed";
        ref string alias = ref (value);
        alias = input;
        command.CommandText = "SELECT Name FROM Items WHERE Name = @name";
        command.Parameters.AddWithValue("@name", value);
        info.ArgumentList.Add(value);
    }

    void Query(string[] inputs)
    {
        { string value = "unrelated sibling"; }
        {
            var commands = from value in inputs
                           select new { Name = value, Command = new SqlCommand("SELECT Name FROM Items WHERE Name = @name") };
            foreach (var entry in commands) entry.Command.Parameters.AddWithValue("@name", entry.Name);
        }
    }
}
