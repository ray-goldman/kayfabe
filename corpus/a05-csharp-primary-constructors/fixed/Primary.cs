using System.Diagnostics;
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
}
