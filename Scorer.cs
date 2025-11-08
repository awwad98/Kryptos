namespace Kryptos;

public class Scorer
{
    private static readonly double[] EnglishFreq = new double[]
    {
        8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,
        0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,
        2.758,0.978,2.360,0.150,1.974,0.074
    };

    private readonly HashSet<string> _common = new(StringComparer.OrdinalIgnoreCase)
    {
        "THE","BE","TO","OF","AND","A","IN","THAT","HAVE","I","IT","FOR","NOT","ON","WITH","HE","AS","YOU","DO","AT","IS","THIS","BUT","BY","FROM"
    };

    public double Score(string plaintext)
    {
        double freq = -ChiSquare(plaintext);
        double words = CommonWordBonus(plaintext) * 20.0;
        double spaces = (plaintext.Count(ch => ch == ' ') / 5.0);
        return freq + words + spaces;
    }

    public double ScorePartial(string partial)
    {
        double c = ChiSquare(partial);
        double lenFactor = Math.Min(1.0, partial.Length / 20.0);
        return -c * lenFactor;
    }

    private double ChiSquare(string text)
    {
        var counts = new double[26];
        int total = 0;
        foreach (var ch in text.ToUpperInvariant())
            if (ch is >= 'A' and <= 'Z') { counts[ch - 'A']++; total++; }

        if (total == 0) return double.PositiveInfinity;

        double chi = 0.0;
        for (int i = 0; i < 26; i++)
        {
            double expected = EnglishFreq[i] * total / 100.0;
            double observed = counts[i];
            double diff = observed - expected;
            chi += diff * diff / (expected > 0 ? expected : 1.0);
        }
        return chi;
    }

    private int CommonWordBonus(string text)
    {
        int m = 0;
        var toks = text.ToUpperInvariant()
            .Split(new char[] { ' ', ',', '.', ';', ':', '\t', '\r', '\n', '!', '?', '-', '(', ')', '"' },
                StringSplitOptions.RemoveEmptyEntries);
        foreach (var t in toks)
            if (t.Length > 1 && _common.Contains(t)) m++;
        return m;
    }
}