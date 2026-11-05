using System.Diagnostics;
using Microsoft.Data.SqlClient;

namespace NamedDomain;

class var
{
    public static implicit operator var(string value) => new var();
    public override string ToString() => System.Environment.GetEnvironmentVariable("QUERY");
}

class Named(string input)
{
    void Run(SqlCommand command, ProcessStartInfo info)
    {
        string value = "fixed";
        command.CommandText = "SELECT " + value;
        info.Arguments = "/c " + value;
    }
}
