using System.Diagnostics;
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
}
