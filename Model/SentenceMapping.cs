using TinyCsvParser.Mapping;

public class SentenceMapping : CsvMapping<Sentence>
{
    public SentenceMapping() : base()
    {
        MapProperty(0, x => x.Sid);
        MapProperty(1, x => x.Text);
    }
}