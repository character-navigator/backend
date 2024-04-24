using TinyCsvParser.Mapping;

public class CsvCharacterMapping : CsvMapping<Character>
{
    public CsvCharacterMapping() : base()
    {
        MapProperty(2, x => x.EndSid);
        MapProperty(3, x => x.Name);
        MapProperty(4, x => x.Summary);
    }
}