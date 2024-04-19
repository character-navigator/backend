using TinyCsvParser.Mapping;
using TinyCsvParser;

public class UserMapping : CsvMapping<User>
{
    public UserMapping() : base()
    {
        MapProperty(0, x => x.Username);
        MapProperty(1, x => x.Password);
    }
}